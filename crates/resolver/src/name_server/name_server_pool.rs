// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{future, Future, TryFutureExt};
use smallvec::SmallVec;
#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
use tokio::runtime::Handle;

use proto::error::ProtoError;
use proto::op::ResponseCode;
use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

use crate::config::{ResolverConfig, ResolverOpts};
#[cfg(feature = "mdns")]
use crate::name_server;
use crate::name_server::{ConnectionProvider, NameServer};
#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
use crate::name_server::{TokioConnection, TokioConnectionProvider};

/// A pool of NameServers
///
/// This is not expected to be used directly, see [`AsyncResolver`].
#[derive(Clone)]
pub struct NameServerPool<
    C: DnsHandle + Send + Sync + 'static,
    P: ConnectionProvider<Conn = C> + Send + 'static,
> {
    // TODO: switch to FuturesMutex (Mutex will have some undesireable locking)
    datagram_conns: Arc<Vec<NameServer<C, P>>>, /* All NameServers must be the same type */
    stream_conns: Arc<Vec<NameServer<C, P>>>,   /* All NameServers must be the same type */
    #[cfg(feature = "mdns")]
    mdns_conns: NameServer<C, P>, /* All NameServers must be the same type */
    options: ResolverOpts,
    conn_provider: P,
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
impl NameServerPool<TokioConnection, TokioConnectionProvider> {
    pub(crate) fn from_config(
        config: &ResolverConfig,
        options: &ResolverOpts,
        runtime: Handle,
    ) -> Self {
        Self::from_config_with_provider(config, options, TokioConnectionProvider::new(runtime))
    }
}

impl<C: DnsHandle + Sync + 'static, P: ConnectionProvider<Conn = C> + 'static>
    NameServerPool<C, P>
{
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
                #[cfg(feature = "dns-over-rustls")]
                let ns_config = {
                    let mut ns_config = ns_config.clone();
                    ns_config.tls_config = config.client_config().clone();
                    ns_config
                };
                #[cfg(not(feature = "dns-over-rustls"))]
                let ns_config = { ns_config.clone() };

                NameServer::<C, P>::new_with_provider(ns_config, *options, conn_provider.clone())
            })
            .collect();

        let stream_conns: Vec<NameServer<C, P>> = config
            .name_servers()
            .iter()
            .filter(|ns_config| ns_config.protocol.is_stream())
            .map(|ns_config| {
                #[cfg(feature = "dns-over-rustls")]
                let ns_config = {
                    let mut ns_config = ns_config.clone();
                    ns_config.tls_config = config.client_config().clone();
                    ns_config
                };
                #[cfg(not(feature = "dns-over-rustls"))]
                let ns_config = { ns_config.clone() };

                NameServer::<C, P>::new_with_provider(ns_config, *options, conn_provider.clone())
            })
            .collect();

        NameServerPool {
            datagram_conns: Arc::new(datagram_conns),
            stream_conns: Arc::new(stream_conns),
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
            datagram_conns: Arc::new(datagram_conns.into_iter().collect()),
            stream_conns: Arc::new(stream_conns.into_iter().collect()),
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
            datagram_conns: Arc::new(datagram_conns.into_iter().collect()),
            stream_conns: Arc::new(stream_conns.into_iter().collect()),
            mdns_conns,
            options: *options,
            conn_provider,
        }
    }

    async fn try_send(
        opts: ResolverOpts,
        conns: Arc<Vec<NameServer<C, P>>>,
        request: DnsRequest,
    ) -> Result<DnsResponse, ProtoError> {
        let mut conns: Vec<NameServer<C, P>> = conns.to_vec();

        // select the highest priority connection
        //   reorder the connections based on current view...
        //   this reorders the inner set
        conns.sort_unstable();
        let request_loop = request.clone();

        parallel_conn_loop(conns, request_loop, opts).await
    }
}

impl<C, P> DnsHandle for NameServerPool<C, P>
where
    C: DnsHandle + Sync + 'static,
    P: ConnectionProvider<Conn = C> + 'static,
{
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>;

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

        // it wasn't a local query, continue with standard lookup path
        let request = mdns.take_request();

        debug!("sending request: {:?}", request.queries());
        // First try the UDP connections
        Box::pin(
            Self::try_send(opts, datagram_conns, request)
                .and_then(move |response| {
                    // handling promotion from datagram to stream base on truncation in message
                    if ResponseCode::NoError == response.response_code() && response.truncated() {
                        // TCP connections should not truncate
                        future::Either::Left(Self::try_send(opts, stream_conns1, tcp_message1))
                    } else {
                        debug!("mDNS responsed for query: {:?}", response.response_code());
                        // Return the result from the UDP connection
                        future::Either::Right(future::ok(response))
                    }
                })
                // if UDP fails, try TCP
                .or_else(move |_| Self::try_send(opts, stream_conns2, tcp_message2)),
        )
    }
}

// TODO: we should be able to have a self-referential future here with Pin and not require cloned conns
/// An async function that will loop over all the conns with a max parallel request count of ops.num_concurrent_req
async fn parallel_conn_loop<C, P>(
    mut conns: Vec<NameServer<C, P>>,
    request: DnsRequest,
    opts: ResolverOpts,
) -> Result<DnsResponse, ProtoError>
where
    C: DnsHandle + 'static,
    P: ConnectionProvider<Conn = C> + 'static,
{
    let mut err = ProtoError::from("No connections available");

    loop {
        let request_cont = request.clone();

        // construct the parallel requests, 2 is the default
        let mut par_conns = SmallVec::<[NameServer<C, P>; 2]>::new();
        let count = conns.len().min(opts.num_concurrent_reqs.max(1));
        for conn in conns.drain(..count) {
            par_conns.push(conn);
        }

        // construct the requests to send
        let requests = if par_conns.is_empty() {
            return Err(err);
        } else {
            par_conns
                .into_iter()
                .map(move |mut conn| conn.send(request_cont.clone()))
        };

        match future::select_ok(requests).await {
            Ok((sent, _)) => return Ok(sent),
            // consider a debug msg here
            Err(e) => {
                err = e;
                continue;
            }
        };
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
        P: ConnectionProvider<Conn = C> + 'static,
        P: ConnectionProvider,
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
    ResolveFuture(Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>),
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
    fn take_future(self) -> Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>> {
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
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match *self {
            Local::ResolveFuture(ref mut ns) => ns.as_mut().poll(cx),
            // TODO: making this a panic for now
            Local::NotMdns(..) => panic!("Local queries that are not mDNS should not be polled"), //Local::NotMdns(message) => return Err(ResolveErrorKind::Message("not mDNS")),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    extern crate env_logger;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::runtime::Runtime;

    use proto::op::Query;
    use proto::rr::{Name, RecordType};
    use proto::xfer::{DnsHandle, DnsRequestOptions};

    use super::*;
    use crate::config::NameServerConfig;
    use crate::config::Protocol;

    #[ignore]
    // because of there is a real connection that needs a reasonable timeout
    #[test]
    fn test_failed_then_success_pool() {
        let config1 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 253),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };

        let config2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let mut io_loop = Runtime::new().unwrap();
        let mut pool = NameServerPool::<_, TokioConnectionProvider>::from_config(
            &resolver_config,
            &ResolverOpts::default(),
            io_loop.handle().clone(),
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
