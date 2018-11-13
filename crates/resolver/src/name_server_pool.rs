// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
//use std::mem;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use futures::future::Loop;
use futures::{future, task, Async, Future, IntoFuture, Poll};
use tokio::executor::{DefaultExecutor, Executor};

use proto::error::{ProtoError, ProtoResult};
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientStream, MdnsQueryType, MDNS_IPV4};
use proto::op::{Edns, NoopMessageFinalizer, ResponseCode};
use proto::tcp::TcpClientStream;
use proto::udp::UdpClientStream;
use proto::xfer::{
    self, BufDnsRequestStreamHandle, DnsExchange, DnsHandle, DnsMultiplexer,
    DnsMultiplexerSerialResponse, DnsRequest, DnsResponse,
};
#[cfg(feature = "dns-over-https")]
use trust_dns_https;

//use async_resolver::BasicAsyncResolver;
use config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

/// State of a connection with a remote NameServer.
#[derive(Clone, Debug)]
enum NameServerState {
    /// Initial state, if Edns is not none, then Edns will be requested
    Init { send_edns: Option<Edns> },
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established { remote_edns: Option<Edns> },
    /// For some reason the connection failed. For UDP this would generally be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should *not* be entered due to an
    ///  error contained in a Message recieved from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed { when: Instant },
}

impl NameServerState {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn to_usize(&self) -> usize {
        match *self {
            NameServerState::Init { .. } => 2,
            NameServerState::Established { .. } => 3,
            NameServerState::Failed { .. } => 1,
        }
    }
}

impl Ord for NameServerState {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_num, other_num) = (self.to_usize(), other.to_usize());
        match self_num.cmp(&other_num) {
            Ordering::Equal => match (self, other) {
                (
                    NameServerState::Failed {
                        when: ref self_when,
                    },
                    NameServerState::Failed {
                        when: ref other_when,
                    },
                ) => {
                    // We reverse, because we want the "older" failures to be tried first...
                    self_when.cmp(other_when).reverse()
                }
                _ => Ordering::Equal,
            },
            cmp => cmp,
        }
    }
}

impl PartialOrd for NameServerState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServerState {
    fn eq(&self, other: &Self) -> bool {
        self.to_usize() == other.to_usize()
    }
}

impl Eq for NameServerState {}

#[derive(Clone, PartialEq, Eq)]
struct NameServerStats {
    state: NameServerState,
    successes: usize,
    failures: usize,
}

impl Default for NameServerStats {
    fn default() -> Self {
        Self::init(None, 0, 0)
    }
}

impl NameServerStats {
    fn init(send_edns: Option<Edns>, successes: usize, failures: usize) -> Self {
        NameServerStats {
            state: NameServerState::Init { send_edns },
            successes,
            failures,
            // TODO: incorporate latency
        }
    }

    fn next_success(&mut self, remote_edns: Option<Edns>) {
        self.successes += 1;

        // update current state

        if remote_edns.is_some() {
            self.state = NameServerState::Established { remote_edns };;
        } else {
            // preserve existing EDNS if it exists
            let remote_edns = if let NameServerState::Established { ref remote_edns } = self.state {
                remote_edns.clone()
            } else {
                None
            };

            self.state = NameServerState::Established { remote_edns };
        };
    }

    fn next_failure(&mut self, error: ProtoError, when: Instant) {
        self.failures += 1;
        debug!("name_server connection failure: {}", error);

        // update current state
        self.state = NameServerState::Failed { when };
    }
}

impl Ord for NameServerStats {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        // otherwise, run our evaluation to determine the next to be returned from the Heap
        //   this will prefer established connections, we should try other connections after
        //   some number to make sure that all are used. This is more important for when
        //   letency is started to be used.
        match self.state.cmp(&other.state) {
            Ordering::Equal => (),
            o => {
                return o;
            }
        }

        // TODO: track latency and use lowest latency connection...

        // invert failure comparison, i.e. the one with the least failures, wins
        if self.failures <= other.failures {
            return Ordering::Greater;
        }

        // at this point we'll go with the lesser of successes to make sure there is ballance
        self.successes.cmp(&other.successes)
    }
}

impl PartialOrd for NameServerStats {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A type to allow for custom ConnectionProviders. Needed mainly for mocking purposes.
pub trait ConnectionProvider: 'static + Clone + Send + Sync {
    type ConnHandle;

    /// The returned handle should
    fn new_connection(config: &NameServerConfig, options: &ResolverOpts) -> Self::ConnHandle;
}

/// Standard connection implements the default mechanism for creating new Connections
#[derive(Clone)]
pub struct StandardConnection;

impl ConnectionProvider for StandardConnection {
    type ConnHandle = ConnectionHandle;

    /// Constructs an initial constructor for the ConnectionHandle to be used to establish a
    ///   future connection.
    fn new_connection(config: &NameServerConfig, options: &ResolverOpts) -> Self::ConnHandle {
        let dns_handle = match config.protocol {
            Protocol::Udp => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Udp {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
            Protocol::Tcp => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Tcp {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Tls {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
                tls_dns_name: config.tls_dns_name.clone().unwrap_or_default(),
            })),
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => {
                ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Https {
                    socket_addr: config.socket_addr,
                    timeout: options.timeout,
                    tls_dns_name: config.tls_dns_name.clone().unwrap_or_default(),
                }))
            }
            #[cfg(feature = "mdns")]
            Protocol::Mdns => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Mdns {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
        };

        ConnectionHandle(Arc::new(Mutex::new(dns_handle)))
    }
}

/// The variants of all supported connections for the Resolver
#[derive(Debug)]
enum ConnectionHandleConnect {
    Udp {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
    Tcp {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
    #[cfg(feature = "dns-over-tls")]
    Tls {
        socket_addr: SocketAddr,
        timeout: Duration,
        tls_dns_name: String,
    },
    #[cfg(feature = "dns-over-https")]
    Https {
        socket_addr: SocketAddr,
        timeout: Duration,
        tls_dns_name: String,
    },
    #[cfg(feature = "mdns")]
    Mdns {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
}

impl ConnectionHandleConnect {
    /// Establishes the connection, this is allowed to perform network operations,
    ///   suchas tokio::spawns of background tasks, etc.
    fn connect(self) -> Result<ConnectionHandleConnected, ProtoError> {
        use self::ConnectionHandleConnect::*;

        debug!("connecting: {:?}", self);
        match self {
            Udp {
                socket_addr,
                timeout,
            } => {
                let (stream, handle) = UdpClientStream::new(socket_addr);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("udp connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::UdpOrTcp(handle))
            }
            Tcp {
                socket_addr,
                timeout,
            } => {
                let (stream, handle) = TcpClientStream::with_timeout(socket_addr, timeout);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    Box::new(stream),
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("tcp connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::UdpOrTcp(handle))
            }
            #[cfg(feature = "dns-over-tls")]
            Tls {
                socket_addr,
                timeout,
                tls_dns_name,
            } => {
                let (stream, handle) = ::tls::new_tls_stream(socket_addr, tls_dns_name);
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    Box::new(handle),
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("tls connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::UdpOrTcp(handle))
            }
            #[cfg(feature = "dns-over-https")]
            Https {
                socket_addr,
                // TODO: https needs timeout!
                timeout: _t,
                tls_dns_name,
            } => {
                let (stream, handle) = ::https::new_https_stream(socket_addr, tls_dns_name);

                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("https connection shutting down: {}", e);
                });

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::Https(handle))
            }
            #[cfg(feature = "mdns")]
            Mdns {
                socket_addr,
                timeout,
            } => {
                let (stream, handle) =
                    MdnsClientStream::new(socket_addr, MdnsQueryType::OneShot, None, None, None);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("mdns connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::UdpOrTcp(handle))
            }
        }
    }
}

/// A representation of an established connection
#[derive(Clone)]
enum ConnectionHandleConnected {
    UdpOrTcp(xfer::BufDnsRequestStreamHandle<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(xfer::BufDnsRequestStreamHandle<trust_dns_https::HttpsSerialResponse>),
}

impl DnsHandle for ConnectionHandleConnected {
    type Response = ConnectionHandleResponseInner;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponseInner {
        match self {
            ConnectionHandleConnected::UdpOrTcp(ref mut conn) => {
                ConnectionHandleResponseInner::UdpOrTcp(conn.send(request))
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionHandleConnected::Https(ref mut https) => {
                ConnectionHandleResponseInner::Https(https.send(request))
            }
        }
    }
}

/// Allows us to wrap a connection that is either pending or already connected
enum ConnectionHandleInner {
    Connect(Option<ConnectionHandleConnect>),
    Connected(ConnectionHandleConnected),
}

impl ConnectionHandleInner {
    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponseInner {
        loop {
            let connected: Result<ConnectionHandleConnected, ProtoError> = match self {
                // still need to connect, drop through
                ConnectionHandleInner::Connect(conn) => {
                    conn.take().expect("already connected?").connect()
                }
                ConnectionHandleInner::Connected(conn) => return conn.send(request),
            };

            match connected {
                Ok(connected) => *self = ConnectionHandleInner::Connected(connected),
                Err(e) => return ConnectionHandleResponseInner::Error(e),
            };
            // continue to return on send...
        }
    }
}

/// ConnectionHandle is used for sending DNS requests to a specific upstream DNS resolver
#[derive(Clone)]
pub struct ConnectionHandle(Arc<Mutex<ConnectionHandleInner>>);

impl DnsHandle for ConnectionHandle {
    type Response = ConnectionHandleResponse;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponse {
        ConnectionHandleResponse(ConnectionHandleResponseInner::ConnectAndRequest {
            conn: self.clone(),
            request: Some(request.into()),
        })
    }
}

/// A wrapper type to switch over a connection that still needs to be made, or is already established
enum ConnectionHandleResponseInner {
    ConnectAndRequest {
        conn: ConnectionHandle,
        request: Option<DnsRequest>,
    },
    UdpOrTcp(xfer::OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(xfer::OneshotDnsResponseReceiver<trust_dns_https::HttpsSerialResponse>),
    Error(ProtoError),
}

impl Future for ConnectionHandleResponseInner {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        use self::ConnectionHandleResponseInner::*;

        trace!("polling response inner");
        loop {
            *self = match self {
                // we still need to check the connection
                ConnectAndRequest {
                    ref conn,
                    ref mut request,
                } => match conn.0.lock() {
                    Ok(mut c) => c.send(request.take().expect("already sent request?")),
                    Err(e) => Error(ProtoError::from(e)),
                },
                UdpOrTcp(ref mut resp) => return resp.poll(),
                #[cfg(feature = "dns-over-https")]
                Https(ref mut https) => return https.poll(),
                Error(ref e) => return Err(e.clone()),
            };

            // ok, connected, loop around and use poll the actual send request
        }
    }
}

/// A future response from a DNS request.
pub struct ConnectionHandleResponse(ConnectionHandleResponseInner);

impl Future for ConnectionHandleResponse {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// Specifies the details of a remote NameServer used for lookups
#[derive(Clone)]
pub struct NameServer<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> {
    config: NameServerConfig,
    options: ResolverOpts,
    client: C,
    // TODO: switch to FuturesMutex? (Mutex will have some undesireable locking)
    stats: Arc<Mutex<NameServerStats>>,
    phantom: PhantomData<P>,
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> Debug for NameServer<C, P> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "config: {:?}, options: {:?}", self.config, self.options)
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> NameServer<C, P> {
    pub fn new(
        config: NameServerConfig,
        options: ResolverOpts,
    ) -> NameServer<ConnectionHandle, StandardConnection> {
        let client = StandardConnection::new_connection(&config, &options);

        // TODO: setup EDNS
        NameServer {
            config,
            options,
            client,
            stats: Arc::new(Mutex::new(NameServerStats::default())),
            phantom: PhantomData,
        }
    }

    #[doc(hidden)]
    pub fn from_conn(
        config: NameServerConfig,
        options: ResolverOpts,
        client: C,
    ) -> NameServer<C, P> {
        NameServer {
            config,
            options,
            client,
            stats: Arc::new(Mutex::new(NameServerStats::default())),
            phantom: PhantomData,
        }
    }

    /// checks if the connection is failed, if so then reconnect.
    fn try_reconnect(&mut self) -> ProtoResult<()> {
        let error_opt: Option<(usize, usize)> = self
            .stats
            .lock()
            .map(|stats| {
                if let NameServerState::Failed { .. } = stats.state {
                    Some((stats.successes, stats.failures))
                } else {
                    None
                }
            }).map_err(|e| {
                ProtoError::from(format!("Error acquiring NameServerStats lock: {}", e))
            })?;

        // if this is in a failure state
        if let Some((successes, failures)) = error_opt {
            debug!("reconnecting: {:?}", self.config);
            // establish a new connection
            self.client = P::new_connection(&self.config, &self.options);

            // reinitialize the mutex (in case it was poisoned before)
            self.stats = Arc::new(Mutex::new(NameServerStats::init(None, successes, failures)));
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl<C, P> DnsHandle for NameServer<C, P>
where
    C: DnsHandle,
    P: ConnectionProvider<ConnHandle = C>,
{
    type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

    fn is_verifying_dnssec(&self) -> bool {
        self.client.is_verifying_dnssec()
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        // if state is failed, return future::err(), unless retry delay expired...
        if let Err(error) = self.try_reconnect() {
            return Box::new(future::err(error));
        }

        let distrust_nx_responses = self.options.distrust_nx_responses;

        // Becuase a Poisoned lock error could have occured, make sure to create a new Mutex...

        // grab a reference to the stats for this NameServer
        let mutex1 = self.stats.clone();
        let mutex2 = self.stats.clone();
        Box::new(
            self.client
                .send(request)
                .and_then(move |response| {
                    // first we'll evaluate if the message succeeded
                    //   see https://github.com/bluejekyll/trust-dns/issues/606
                    //   TODO: there are probably other return codes from the server we may want to
                    //    retry on. We may also want to evaluate NoError responses that lack records as errors as well
                    if distrust_nx_responses {
                        if let ResponseCode::ServFail = response.response_code() {
                            let note = "Nameserver responded with SERVFAIL";
                            debug!("{}", note);
                            return Err(ProtoError::from(note));
                        }
                    }

                    Ok(response)
                })
                .and_then(move |response| {
                    // TODO: consider making message::take_edns...
                    let remote_edns = response.edns().cloned();

                    // this transitions the state to success
                    let response = mutex1
                        .lock()
                        .and_then(|mut stats| {
                            stats.next_success(remote_edns);
                            Ok(response)
                        })
                        .map_err(|e| {
                            ProtoError::from(format!("Error acquiring NameServerStats lock: {}", e))
                        });

                    future::result(response)
                })
                .or_else(move |error| {
                    // this transitions the state to failure
                    mutex2
                        .lock()
                        .and_then(|mut stats| {
                            stats.next_failure(error.clone(), Instant::now());
                            Ok(())
                        })
                        .or_else(|e| {
                            warn!("Error acquiring NameServerStats lock (already in error state, ignoring): {}", e);
                            Err(())
                        })
                        .is_ok(); // ignoring error, as this connection is already marked in error...

                    // These are connection failures, not lookup failures, that is handled in the resolver layer
                    future::err(error)
                }),
        )
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> Ord for NameServer<C, P> {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        self.stats
            .lock()
            .expect("poisoned lock in NameServer::cmp")
            .cmp(
                &other
                      .stats
                      .lock() // TODO: hmm... deadlock potential? switch to try_lock?
                      .expect("poisoned lock in NameServer::cmp"),
            )
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> PartialOrd for NameServer<C, P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> PartialEq for NameServer<C, P> {
    /// NameServers are equal if the config (connection information) are equal
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> Eq for NameServer<C, P> {}

// TODO: once IPv6 is better understood, also make this a binary keep.
#[cfg(feature = "mdns")]
fn mdns_nameserver(options: ResolverOpts) -> NameServer<ConnectionHandle, StandardConnection> {
    let config = NameServerConfig {
        socket_addr: *MDNS_IPV4,
        protocol: Protocol::Mdns,
        tls_dns_name: None,
    };
    NameServer::<_, StandardConnection>::new(config, options)
}

/// A pool of NameServers
///
/// This is not expected to be used directly, see `ResolverFuture`.
#[derive(Clone)]
pub struct NameServerPool<C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> {
    // TODO: switch to FuturesMutex (Mutex will have some undesireable locking)
    datagram_conns: Arc<Mutex<Vec<NameServer<C, P>>>>, /* All NameServers must be the same type */
    stream_conns: Arc<Mutex<Vec<NameServer<C, P>>>>,   /* All NameServers must be the same type */
    #[cfg(feature = "mdns")]
    mdns_conns: NameServer<C, P>, /* All NameServers must be the same type */
    options: ResolverOpts,
    phantom: PhantomData<P>,
}

impl<C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> NameServerPool<C, P> {
    pub(crate) fn from_config(
        config: &ResolverConfig,
        options: &ResolverOpts,
    ) -> NameServerPool<ConnectionHandle, StandardConnection> {
        let datagram_conns: Vec<NameServer<ConnectionHandle, StandardConnection>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_datagram())
            .map(|ns_config| NameServer::<_, StandardConnection>::new(ns_config.clone(), *options))
            .collect();

        let stream_conns: Vec<NameServer<ConnectionHandle, StandardConnection>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_stream())
            .map(|ns_config| NameServer::<_, StandardConnection>::new(ns_config.clone(), *options))
            .collect();

        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns)),
            stream_conns: Arc::new(Mutex::new(stream_conns)),
            #[cfg(feature = "mdns")]
            mdns_conns: mdns_nameserver(*options),
            options: *options,
            phantom: PhantomData,
        }
    }

    #[doc(hidden)]
    #[cfg(not(feature = "mdns"))]
    pub fn from_nameservers(
        options: &ResolverOpts,
        datagram_conns: Vec<NameServer<C, P>>,
        stream_conns: Vec<NameServer<C, P>>,
    ) -> Self {
        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns.into_iter().collect())),
            stream_conns: Arc::new(Mutex::new(stream_conns.into_iter().collect())),
            options: *options,
            phantom: PhantomData,
        }
    }

    #[doc(hidden)]
    #[cfg(feature = "mdns")]
    pub fn from_nameservers(
        options: &ResolverOpts,
        datagram_conns: Vec<NameServer<C, P>>,
        stream_conns: Vec<NameServer<C, P>>,
        mdns_conns: NameServer<C, P>,
    ) -> Self {
        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns.into_iter().collect())),
            stream_conns: Arc::new(Mutex::new(stream_conns.into_iter().collect())),
            mdns_conns,
            options: *options,
            phantom: PhantomData,
        }
    }

    fn try_send(conns: Arc<Mutex<Vec<NameServer<C, P>>>>, request: DnsRequest) -> TrySend<C, P> {
        TrySend::Lock {
            conns,
            request: Some(request),
        }
    }
}

impl<C, P> DnsHandle for NameServerPool<C, P>
where
    C: DnsHandle + 'static,
    P: ConnectionProvider<ConnHandle = C> + 'static,
{
    type Response = Box<Future<Item = DnsResponse, Error = ProtoError> + Send>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request = request.into();
        let datagram_conns = Arc::clone(&self.datagram_conns);
        let stream_conns1 = Arc::clone(&self.stream_conns);
        let stream_conns2 = Arc::clone(&self.stream_conns);
        // TODO: remove this clone, return the Message in the error?
        let tcp_message1 = request.clone();
        let tcp_message2 = request.clone();

        // if it's a .local. query, then we *only* query mDNS, these should never be sent on to upstream resolvers
        #[cfg(feature = "mdns")]
        let mdns = mdns::maybe_local(&mut self.mdns_conns, request);

        // TODO: limited to only when mDNS is enabled, but this should probably always be enforced?
        #[cfg(not(feature = "mdns"))]
        let mdns = Local::NotMdns(request);

        // local queries are queried through mDNS
        if mdns.is_local() {
            return mdns.take_future();
        }

        // TODO: should we allow mDNS to be used for standard lookups as well?

        // it wasn't a local query, continue with standard looup path
        let request = mdns.take_request();
        Box::new(
            // First try the UDP connections
            Self::try_send(datagram_conns, request)
                .and_then(move |response| {
                    // handling promotion from datagram to stream base on truncation in message
                    if ResponseCode::NoError == response.response_code() && response.truncated() {
                        // TCP connections should not truncate
                        future::Either::A(Self::try_send(stream_conns1, tcp_message1))
                    } else {
                        // Return the result from the UDP connection
                        future::Either::B(future::ok(response))
                    }
                })
                // if UDP fails, try TCP
                .or_else(move |_| Self::try_send(stream_conns2, tcp_message2)),
        )
    }
}

enum TrySend<C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> {
    Lock {
        conns: Arc<Mutex<Vec<NameServer<C, P>>>>,
        request: Option<DnsRequest>,
    },
    DoSend(Box<Future<Item = DnsResponse, Error = ProtoError> + Send>),
}

impl<C, P> Future for TrySend<C, P>
where
    C: DnsHandle + 'static,
    P: ConnectionProvider<ConnHandle = C> + 'static,
{
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // TODO: this resolves an odd unsized issue with the loop_fn future
        use std::mem;
        let future;

        match *self {
            TrySend::Lock {
                ref conns,
                ref mut request,
            } => {
                // pull a lock on the shared connections, lock releases at the end of the method
                let conns = conns.try_lock();
                match conns {
                    Err(TryLockError::Poisoned(_)) => {
                        // TODO: what to do on poisoned errors? this is non-recoverable, right?
                        return Err(ProtoError::from("Lock Poisoned"));
                    }
                    Err(TryLockError::WouldBlock) => {
                        // since there is nothing registered with Tokio, we need to yield...
                        task::current().notify();
                        return Ok(Async::NotReady);
                    }
                    Ok(mut conns) => {
                        // select the highest priority connection
                        //   reorder the connections based on current view...
                        //   this reorders the inner set
                        conns.sort_unstable();

                        // TODO: restrict this size to a maximum # of NameServers to try
                        let mut conns: Vec<NameServer<C, P>> = conns.clone(); // get a stable view for trying all connections
                        let request = mem::replace(request, None);
                        let request = request.expect("bad state, mesage should never be None");
                        let request_loop = request.clone();

                        let loop_future = future::loop_fn(
                            (
                                conns,
                                request_loop,
                                ProtoError::from("No connections available"),
                            ),
                            |(mut conns, request, err)| {
                                let conn = conns.pop();

                                let request_cont = request.clone();

                                conn.ok_or_else(move || err).into_future().and_then(
                                    move |mut conn| {
                                        conn.send(request).then(|sent_res| match sent_res {
                                            Ok(sent) => Ok(Loop::Break(sent)),
                                            Err(err) => {
                                                Ok(Loop::Continue((conns, request_cont, err)))
                                            }
                                        })
                                    },
                                )
                            },
                        );

                        future = Box::new(loop_future);
                    }
                }
            }
            TrySend::DoSend(ref mut future) => return future.poll(),
        }

        // can only get here if we were in the TrySend::Lock state
        *self = TrySend::DoSend(future);

        task::current().notify();
        Ok(Async::NotReady)
    }
}

#[cfg(feature = "mdns")]
mod mdns {
    use super::*;

    use proto::rr::domain::usage;
    use proto::DnsHandle;

    /// Returns true
    pub fn maybe_local<C, P>(name_server: &mut NameServer<C, P>, request: DnsRequest) -> Local
    where
        C: DnsHandle + 'static,
        P: ConnectionProvider<ConnHandle = C> + 'static,
    {
        if request
            .queries()
            .iter()
            .any(|query| usage::LOCAL.name().zone_of(query.name()))
        {
            Local::ResolveFuture(name_server.send(request))
        } else {
            Local::NotMdns(request)
        }
    }
}

pub enum Local {
    ResolveFuture(Box<Future<Item = DnsResponse, Error = ProtoError> + Send>),
    NotMdns(DnsRequest),
}

impl Local {
    fn is_local(&self) -> bool {
        if let Local::ResolveFuture(..) = *self {
            true
        } else {
            false
        }
    }

    /// Takes the future
    ///
    /// # Panics
    ///
    /// Panics if this is in fact a Local::NotMdns
    fn take_future(self) -> Box<Future<Item = DnsResponse, Error = ProtoError> + Send> {
        match self {
            Local::ResolveFuture(future) => future,
            _ => panic!("non Local queries have no future, see take_message()"),
        }
    }

    /// Takes the message
    ///
    /// # Panics
    ///
    /// Panics if this is in fact a Local::ResolveFuture
    fn take_request(self) -> DnsRequest {
        match self {
            Local::NotMdns(request) => request,
            _ => panic!("Local queries must be polled, see take_future()"),
        }
    }
}

impl Future for Local {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
                Local::ResolveFuture(ref mut ns) => ns.poll(),
                // TODO: making this a panic for now
                Local::NotMdns(..) => {
                    panic!("Local queries that are not mDNS should not be polled")
                }
                //Local::NotMdns(message) => return Err(ResolveErrorKind::Message("not mDNS")),
            }
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use futures::future;
    use tokio::runtime::current_thread::Runtime;

    use proto::op::{Query, ResponseCode};
    use proto::rr::{Name, RecordType};
    use proto::xfer::{DnsHandle, DnsRequestOptions};

    use super::*;
    use config::Protocol;

    #[test]
    fn test_state_cmp() {
        let init = NameServerStats {
            state: NameServerState::Init { send_edns: None },
            successes: 0,
            failures: 0,
        };

        let established = NameServerStats {
            state: NameServerState::Established { remote_edns: None },
            successes: 0,
            failures: 0,
        };

        let failed = NameServerStats {
            state: NameServerState::Failed {
                when: Instant::now(),
            },
            successes: 0,
            failures: 0,
        };

        let established_successes = NameServerStats {
            state: NameServerState::Established { remote_edns: None },
            successes: 1,
            failures: 0,
        };

        let established_failed = NameServerStats {
            state: NameServerState::Established { remote_edns: None },
            successes: 0,
            failures: 1,
        };

        assert_eq!(init.cmp(&init), Ordering::Equal);
        assert_eq!(init.cmp(&established), Ordering::Less);
        assert_eq!(established.cmp(&failed), Ordering::Greater);
        assert_eq!(established.cmp(&established_successes), Ordering::Greater);
        assert_eq!(established.cmp(&established_failed), Ordering::Greater);
    }

    #[test]
    fn test_name_server() {
        env_logger::try_init().ok();

        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        };
        let mut io_loop = Runtime::new().unwrap();
        let name_server = future::lazy(|| {
            future::ok(NameServer::<_, StandardConnection>::new(
                config,
                ResolverOpts::default(),
            ))
        });

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = io_loop
            .block_on(name_server.and_then(|mut name_server| {
                name_server.lookup(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default(),
                )
            })).expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[test]
    fn test_failed_name_server() {
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_millis(1); // this is going to fail, make it fail fast...
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 252),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        };
        let mut io_loop = Runtime::new().unwrap();
        let name_server =
            future::lazy(|| future::ok(NameServer::<_, StandardConnection>::new(config, options)));

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(
            io_loop
                .block_on(name_server.and_then(|mut name_server| name_server.lookup(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default()
                ))).is_err()
        );
    }

    #[ignore]
    // because of there is a real connection that needs a reasonable timeout
    #[test]
    fn test_failed_then_success_pool() {
        let config1 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 253),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        };

        let config2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        };

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let mut io_loop = Runtime::new().unwrap();
        let mut pool = NameServerPool::<_, StandardConnection>::from_config(
            &resolver_config,
            &ResolverOpts::default(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();

        // TODO: it's not clear why there are two failures before the success
        for i in 0..2 {
            assert!(
                io_loop
                    .block_on(pool.lookup(
                        Query::query(name.clone(), RecordType::A),
                        DnsRequestOptions::default()
                    )).is_err(),
                "iter: {}",
                i
            );
        }

        for i in 0..10 {
            assert!(
                io_loop
                    .block_on(pool.lookup(
                        Query::query(name.clone(), RecordType::A),
                        DnsRequestOptions::default()
                    )).is_ok(),
                "iter: {}",
                i
            );
        }
    }
}
