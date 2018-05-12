// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::marker::PhantomData;
use std::mem;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Instant;

use futures::{future, task, Async, Future, Poll};

#[cfg(feature = "mdns")]
use trust_dns_proto::multicast::{MDNS_IPV4, MdnsClientStream, MdnsQueryType};
use trust_dns_proto::op::{Edns, NoopMessageFinalizer, ResponseCode};
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::udp::UdpClientStream;
use trust_dns_proto::xfer::{DnsFuture, DnsHandle, DnsRequest, DnsResponse};

use config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use error::*;
use resolver_future::BasicResolverHandle;

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
    fn to_usize(&self) -> usize {
        match *self {
            NameServerState::Init { .. } => 3,
            NameServerState::Established { .. } => 2,
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
            mem::replace(
                &mut self.state,
                NameServerState::Established { remote_edns },
            );
        } else {
            // preserve existing EDNS if it exists
            let remote_edns = if let NameServerState::Established { ref remote_edns } = self.state {
                remote_edns.clone()
            } else {
                None
            };

            mem::replace(
                &mut self.state,
                NameServerState::Established { remote_edns },
            );
        };
    }

    fn next_failure(&mut self, error: ResolveError, when: Instant) {
        self.failures += 1;
        debug!("name_server connection failure: {}", error);

        // update current state
        mem::replace(&mut self.state, NameServerState::Failed { when });
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
        match self.state.cmp(&other.state) {
            Ordering::Equal => (),
            o @ _ => {
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

#[doc(hidden)]
pub trait ConnectionProvider: 'static + Clone + Send + Sync {
    type ConnHandle;

    fn new_connection(config: &NameServerConfig, options: &ResolverOpts) -> Self::ConnHandle;
}

/// Standard connection implements the default mechanism for creating new Connections
#[derive(Clone)]
pub struct StandardConnection;

impl ConnectionProvider for StandardConnection {
    type ConnHandle = BasicResolverHandle;

    fn new_connection(config: &NameServerConfig, options: &ResolverOpts) -> Self::ConnHandle {
        let dns_handle = match config.protocol {
            Protocol::Udp => {
                let (stream, handle) = UdpClientStream::new(config.socket_addr);
                // TODO: need config for Signer...
                DnsFuture::with_timeout(
                    stream,
                    handle,
                    options.timeout,
                    NoopMessageFinalizer::new(),
                )
            }
            Protocol::Tcp => {
                let (stream, handle) =
                    TcpClientStream::with_timeout(config.socket_addr, options.timeout);
                // TODO: need config for Signer...
                DnsFuture::with_timeout(
                    stream,
                    handle,
                    options.timeout,
                    NoopMessageFinalizer::new(),
                )
            }
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => {
                let (stream, handle) = ::tls::new_tls_stream(
                    config.socket_addr,
                    config.tls_dns_name.clone().unwrap_or_default(),
                );
                DnsFuture::with_timeout(
                    stream,
                    handle,
                    options.timeout,
                    NoopMessageFinalizer::new(),
                )
            }
            // TODO: Protocol::Tls => TlsClientStream::new(config.socket_addr),
            #[cfg(feature = "mdns")]
            Protocol::Mdns => {
                let (stream, handle) = MdnsClientStream::new(
                    config.socket_addr,
                    MdnsQueryType::OneShot,
                    None,
                    None,
                    None,
                );
                // TODO: need config for Signer...
                DnsFuture::with_timeout(
                    stream,
                    handle,
                    options.timeout,
                    NoopMessageFinalizer::new(),
                )
            }
        };

        BasicResolverHandle::new(dns_handle)
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

impl<C: DnsHandle, P: ConnectionProvider<ConnHandle = C>> NameServer<C, P> {
    pub fn new(
        config: NameServerConfig,
        options: ResolverOpts,
    ) -> NameServer<BasicResolverHandle, StandardConnection> {
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
    fn try_reconnect(&mut self) -> ResolveResult<()> {
        let error_opt: Option<(usize, usize)> = self.stats
            .lock()
            .map(|stats| {
                if let NameServerState::Failed { .. } = stats.state {
                    Some((stats.successes, stats.failures))
                } else {
                    None
                }
            })
            .map_err(|e| {
                ResolveErrorKind::Msg(format!("Error acquiring NameServerStats lock: {}", e).into())
            })?;

        // if this is in a failure state
        if let Some((successes, failures)) = error_opt {
            debug!("reconnecting: {:?}", self.config);
            // establish a new connection
            let client = P::new_connection(&self.config, &self.options);
            mem::replace(&mut self.client, client);

            // reinitialize the mutex (in case it was poisoned before)
            mem::replace(
                &mut self.stats,
                Arc::new(Mutex::new(NameServerStats::init(None, successes, failures))),
            );
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl<C, P> DnsHandle for NameServer<C, P>
where
    C: DnsHandle<Error = ResolveError>,
    P: ConnectionProvider<ConnHandle = C>,
{
    type Error = ResolveError;

    fn is_verifying_dnssec(&self) -> bool {
        self.client.is_verifying_dnssec()
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send<R: Into<DnsRequest>>(
        &mut self,
        request: R,
    ) -> Box<Future<Item = DnsResponse, Error = Self::Error> + Send> {
        // if state is failed, return future::err(), unless retry delay expired...
        if let Err(error) = self.try_reconnect() {
            return Box::new(future::err(error));
        }

        // Becuase a Poisoned lock error could have occured, make sure to create a new Mutex...

        // grab a reference to the stats for this NameServer
        let mutex1 = self.stats.clone();
        let mutex2 = self.stats.clone();
        Box::new(
            self.client
                .send(request)
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
                        .map_err(|e| format!("Error acquiring NameServerStats lock: {}", e).into());

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
            .cmp(&other
                      .stats
                      .lock() // TODO: hmm... deadlock potential? switch to try_lock?
                      .expect("poisoned lock in NameServer::cmp"))
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
fn mdns_nameserver(options: ResolverOpts) -> NameServer<BasicResolverHandle, StandardConnection> {
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
    ) -> NameServerPool<BasicResolverHandle, StandardConnection> {
        let datagram_conns: Vec<NameServer<BasicResolverHandle, StandardConnection>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_datagram())
            .map(|ns_config| {
                NameServer::<_, StandardConnection>::new(ns_config.clone(), options.clone())
            })
            .collect();

        let stream_conns: Vec<NameServer<BasicResolverHandle, StandardConnection>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_stream())
            .map(|ns_config| {
                NameServer::<_, StandardConnection>::new(ns_config.clone(), options.clone())
            })
            .collect();

        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns)),
            stream_conns: Arc::new(Mutex::new(stream_conns)),
            #[cfg(feature = "mdns")]
            mdns_conns: mdns_nameserver(options.clone()),
            options: options.clone(),
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
            options: options.clone(),
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
            mdns_conns: mdns_conns,
            options: options.clone(),
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
    C: DnsHandle<Error = ResolveError> + 'static,
    P: ConnectionProvider<ConnHandle = C> + 'static,
{
    type Error = ResolveError;

    fn send<R: Into<DnsRequest>>(
        &mut self,
        request: R,
    ) -> Box<Future<Item = DnsResponse, Error = Self::Error> + Send> {
        let request = request.into();
        let datagram_conns = self.datagram_conns.clone();
        let stream_conns1 = self.stream_conns.clone();
        let stream_conns2 = self.stream_conns.clone();
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
    DoSend(Box<Future<Item = DnsResponse, Error = ResolveError> + Send>),
}

impl<C, P> Future for TrySend<C, P>
where
    C: DnsHandle<Error = ResolveError> + 'static,
    P: ConnectionProvider<ConnHandle = C> + 'static,
{
    type Item = DnsResponse;
    type Error = ResolveError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
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
                        return Err(ResolveErrorKind::Msg("Lock Poisoned".to_string()).into());
                    }
                    Err(TryLockError::WouldBlock) => {
                        // since there is nothing registered with Tokio, we need to yield...
                        task::current().notify();
                        return Ok(Async::NotReady);
                    }
                    Ok(mut conns) => {
                        // select the highest priority connection
                        //   reorder the connections based on current view...
                        conns.sort_unstable();
                        let mut conns = conns.clone(); // get a stable view for trying all connections
                        let conn = conns.pop();

                        if conn.is_none() {
                            return Err(ResolveErrorKind::Message("No connections available").into());
                        }

                        let message = mem::replace(request, None);
                        future = conn.unwrap()
                            .send(message.expect("bad state, mesage should never be None"));
                    }
                }
            }
            TrySend::DoSend(ref mut future) => return future.poll(),
        }

        // can only get here if we were in the TrySend::Lock state
        mem::replace(self, TrySend::DoSend(future));

        task::current().notify();
        Ok(Async::NotReady)
    }
}

#[cfg(feature = "mdns")]
mod mdns {
    use super::*;

    use trust_dns_proto::rr::domain::usage;
    use trust_dns_proto::DnsHandle;

    /// Returns true
    pub fn maybe_local<C, P>(name_server: &mut NameServer<C, P>, request: DnsRequest) -> Local
    where
        C: DnsHandle<Error = ResolveError> + 'static,
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
    ResolveFuture(Box<Future<Item = DnsResponse, Error = ResolveError> + Send>),
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
    fn take_future(self) -> Box<Future<Item = DnsResponse, Error = ResolveError> + Send> {
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
    type Error = ResolveError;

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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use futures::future;
    use tokio::runtime::current_thread::Runtime;

    use trust_dns_proto::op::{Query, ResponseCode};
    use trust_dns_proto::rr::{Name, RecordType};
    use trust_dns_proto::xfer::{DnsHandle, DnsRequestOptions};

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
        assert_eq!(init.cmp(&established), Ordering::Greater);
        assert_eq!(established.cmp(&failed), Ordering::Greater);
        assert_eq!(established.cmp(&established_successes), Ordering::Greater);
        assert_eq!(established.cmp(&established_failed), Ordering::Greater);
    }

    #[test]
    fn test_name_server() {
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
            }))
            .expect("query failed");
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
                )))
                .is_err()
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
                    ))
                    .is_err(),
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
                    ))
                    .is_ok(),
                "iter: {}",
                i
            );
        }
    }
}
