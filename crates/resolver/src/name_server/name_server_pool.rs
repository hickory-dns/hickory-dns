// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::{Arc, Mutex, TryLockError};

use futures::future::Loop;
use futures::{future, task, Async, Future, IntoFuture, Poll};
use smallvec::SmallVec;

use proto::error::ProtoError;
use proto::op::ResponseCode;
use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

use config::{ResolverConfig, ResolverOpts};
use name_server::{NameServer, ConnectionHandle, ConnectionProvider, StandardConnection};
#[cfg(feature = "mdns")]
use name_server;

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
    conn_provider: P,
}

impl NameServerPool<ConnectionHandle, StandardConnection> {
    pub(crate) fn from_config(config: &ResolverConfig, options: &ResolverOpts) -> Self {
        Self::from_config_with_provider(config, options, StandardConnection)
    }
}

impl<C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> NameServerPool<C, P> {
    pub(crate) fn from_config_with_provider(
        config: &ResolverConfig,
        options: &ResolverOpts,
        conn_provider: P,
    ) -> NameServerPool<C, P> {
        let datagram_conns: Vec<NameServer<C, P>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_datagram())
            .map(|ns_config| {
                NameServer::<C, P>::new_with_provider(
                    ns_config.clone(),
                    *options,
                    conn_provider.clone(),
                )
            }).collect();

        let stream_conns: Vec<NameServer<C, P>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_stream())
            .map(|ns_config| {
                NameServer::<C, P>::new_with_provider(
                    ns_config.clone(),
                    *options,
                    conn_provider.clone(),
                )
            }).collect();

        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns)),
            stream_conns: Arc::new(Mutex::new(stream_conns)),
            #[cfg(feature = "mdns")]
            mdns_conns: name_server::mdns_nameserver(*options, conn_provider.clone()),
            options: *options,
            conn_provider,
        }
    }

    #[doc(hidden)]
    #[cfg(not(feature = "mdns"))]
    pub fn from_nameservers(
        options: &ResolverOpts,
        datagram_conns: Vec<NameServer<C, P>>,
        stream_conns: Vec<NameServer<C, P>>,
        conn_provider: P,
    ) -> Self {
        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns.into_iter().collect())),
            stream_conns: Arc::new(Mutex::new(stream_conns.into_iter().collect())),
            options: *options,
            conn_provider,
        }
    }

    #[doc(hidden)]
    #[cfg(feature = "mdns")]
    pub fn from_nameservers(
        options: &ResolverOpts,
        datagram_conns: Vec<NameServer<C, P>>,
        stream_conns: Vec<NameServer<C, P>>,
        mdns_conns: NameServer<C, P>,
        conn_provider: P,
    ) -> Self {
        NameServerPool {
            datagram_conns: Arc::new(Mutex::new(datagram_conns.into_iter().collect())),
            stream_conns: Arc::new(Mutex::new(stream_conns.into_iter().collect())),
            mdns_conns,
            options: *options,
            conn_provider,
        }
    }

    fn try_send(
        opts: ResolverOpts,
        conns: Arc<Mutex<Vec<NameServer<C, P>>>>,
        request: DnsRequest,
    ) -> TrySend<C, P> {
        TrySend::Lock {
            opts,
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
        let opts = self.options;
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
            Self::try_send(opts, datagram_conns, request)
                .and_then(move |response| {
                    // handling promotion from datagram to stream base on truncation in message
                    if ResponseCode::NoError == response.response_code() && response.truncated() {
                        // TCP connections should not truncate
                        future::Either::A(Self::try_send(opts, stream_conns1, tcp_message1))
                    } else {
                        // Return the result from the UDP connection
                        future::Either::B(future::ok(response))
                    }
                })
                // if UDP fails, try TCP
                .or_else(move |_| Self::try_send(opts, stream_conns2, tcp_message2)),
        )
    }
}

#[allow(clippy::large_enum_variant)]
enum TrySend<C: DnsHandle + 'static, P: ConnectionProvider<ConnHandle = C> + 'static> {
    Lock {
        opts: ResolverOpts,
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
        let future;

        match *self {
            TrySend::Lock {
                ref opts,
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
                        let opts = *opts;

                        // select the highest priority connection
                        //   reorder the connections based on current view...
                        //   this reorders the inner set
                        conns.sort_unstable();

                        // TODO: restrict this size to a maximum # of NameServers to try
                        // get a stable view for trying all connections
                        //   we split into chunks of the numeber of parallel requests to issue
                        let mut conns: Vec<NameServer<C, P>> = conns.clone();
                        let request = request.take();
                        let request = request.expect("bad state, mesage should never be None");
                        let request_loop = request.clone();

                        let loop_future = future::loop_fn(
                            (
                                conns,
                                request_loop,
                                ProtoError::from("No connections available"),
                            ),
                            move |(mut conns, request, err)| {
                                let request_cont = request.clone();

                                // construct the parallel requests, 2 is the default
                                let mut par_conns = SmallVec::<[NameServer<C, P>; 2]>::new();
                                let count = conns.len().min(opts.num_concurrent_reqs.max(1));
                                for conn in conns.drain(..count) {
                                    par_conns.push(conn);
                                }

                                // construct the requests to send
                                let requests = if par_conns.is_empty() {
                                    None
                                } else {
                                    Some(
                                        par_conns
                                            .into_iter()
                                            .map(move |mut conn| conn.send(request.clone())),
                                    )
                                };

                                // execute all the requests
                                requests.ok_or_else(move || err).into_future().and_then(
                                    |requests| {
                                        futures::select_ok(requests)
                                            .and_then(|(sent, _)| Ok(Loop::Break(sent)))
                                            .or_else(move |err| {
                                                Ok(Loop::Continue((conns, request_cont, err)))
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
    #[allow(dead_code)]
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

    use tokio::runtime::current_thread::Runtime;

    use proto::op::Query;
    use proto::rr::{Name, RecordType};
    use proto::xfer::{DnsHandle, DnsRequestOptions};

    use super::*;
    use config::Protocol;
    use config::NameServerConfig;

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
