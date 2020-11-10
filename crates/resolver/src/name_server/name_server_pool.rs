// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::{future::Future, future::FutureExt};
use smallvec::SmallVec;

use proto::xfer::{DnsHandle, DnsRequest, DnsResponse};
use proto::Time;

use crate::config::{ResolverConfig, ResolverOpts};
use crate::error::{ResolveError, ResolveErrorKind};
#[cfg(feature = "mdns")]
use crate::name_server;
use crate::name_server::{ConnectionProvider, NameServer};
#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
use crate::name_server::{TokioConnection, TokioConnectionProvider, TokioHandle};

/// A pool of NameServers
///
/// This is not expected to be used directly, see [`AsyncResolver`].
#[derive(Clone)]
pub struct NameServerPool<
    C: DnsHandle<Error = ResolveError> + Send + Sync + 'static,
    P: ConnectionProvider<Conn = C> + Send + 'static,
> {
    // TODO: switch to FuturesMutex (Mutex will have some undesireable locking)
    datagram_conns: Arc<[NameServer<C, P>]>, /* All NameServers must be the same type */
    stream_conns: Arc<[NameServer<C, P>]>,   /* All NameServers must be the same type */
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
        runtime: TokioHandle,
    ) -> Self {
        Self::from_config_with_provider(config, options, TokioConnectionProvider::new(runtime))
    }
}

impl<C, P> NameServerPool<C, P>
where
    C: DnsHandle<Error = ResolveError> + Sync + 'static,
    P: ConnectionProvider<Conn = C> + 'static,
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
            datagram_conns: Arc::from(datagram_conns),
            stream_conns: Arc::from(stream_conns),
            #[cfg(feature = "mdns")]
            mdns_conns: name_server::mdns_nameserver(*options, conn_provider.clone(), false),
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
            datagram_conns: Arc::from(datagram_conns),
            stream_conns: Arc::from(stream_conns),
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
            datagram_conns: Arc::from(datagram_conns),
            stream_conns: Arc::from(stream_conns),
            mdns_conns,
            options: *options,
            conn_provider,
        }
    }

    #[cfg(test)]
    #[cfg(not(feature = "mdns"))]
    fn from_nameservers_test(
        options: &ResolverOpts,
        datagram_conns: Arc<[NameServer<C, P>]>,
        stream_conns: Arc<[NameServer<C, P>]>,
        conn_provider: P,
    ) -> Self {
        NameServerPool {
            datagram_conns,
            stream_conns,
            options: *options,
            conn_provider,
        }
    }

    #[cfg(test)]
    #[cfg(feature = "mdns")]
    fn from_nameservers_test(
        options: &ResolverOpts,
        datagram_conns: Arc<[NameServer<C, P>]>,
        stream_conns: Arc<[NameServer<C, P>]>,
        mdns_conns: NameServer<C, P>,
        conn_provider: P,
    ) -> Self {
        NameServerPool {
            datagram_conns,
            stream_conns,
            mdns_conns,
            options: *options,
            conn_provider,
        }
    }

    async fn try_send(
        opts: ResolverOpts,
        conns: Arc<[NameServer<C, P>]>,
        request: DnsRequest,
    ) -> Result<DnsResponse, ResolveError> {
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
    C: DnsHandle<Error = ResolveError> + Sync + 'static,
    P: ConnectionProvider<Conn = C> + 'static,
{
    type Response = Pin<Box<dyn Future<Output = Result<DnsResponse, ResolveError>> + Send>>;
    type Error = ResolveError;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let opts = self.options;
        let request = request.into();
        let datagram_conns = Arc::clone(&self.datagram_conns);
        let stream_conns = Arc::clone(&self.stream_conns);
        // TODO: remove this clone, return the Message in the error?
        let tcp_message = request.clone();

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

        Box::pin(async move {
            debug!("sending request: {:?}", request.queries());

            // First try the UDP connections
            let udp_res = Self::try_send(opts, datagram_conns, request).await;

            let udp_res = match udp_res {
                // handling promotion from datagram to stream base on truncation in message
                Ok(response) if !response.truncated() => {
                    return Ok(response);
                }
                Ok(response) => {
                    debug!("truncated response received, continuing to TCP");
                    Ok(response)
                }
                Err(e) => Err(e),
            };

            // no TCP connections available
            if stream_conns.is_empty() {
                return udp_res;
            }

            // UDP failed trying TCP connections
            let tcp_res = Self::try_send(opts, stream_conns, tcp_message).await;

            let tcp_err = match tcp_res {
                res @ Ok(..) => return res,
                Err(e) => e,
            };

            // Even if the UDP result was truncated, return that
            let udp_err = match udp_res {
                Ok(response) => return Ok(response),
                Err(e) => e,
            };

            match udp_err.cmp_specificity(&tcp_err) {
                Ordering::Greater => Err(udp_err),
                _ => Err(tcp_err),
            }
        })
    }
}

// TODO: we should be able to have a self-referential future here with Pin and not require cloned conns
/// An async function that will loop over all the conns with a max parallel request count of ops.num_concurrent_req
async fn parallel_conn_loop<C, P>(
    mut conns: Vec<NameServer<C, P>>,
    request: DnsRequest,
    opts: ResolverOpts,
) -> Result<DnsResponse, ResolveError>
where
    C: DnsHandle<Error = ResolveError> + 'static,
    P: ConnectionProvider<Conn = C> + 'static,
{
    let mut err = ResolveError::from("No connections available");
    // If the name server we're trying is giving us backpressure by returning ProtoErrorKind::Busy,
    // we will first try the other name servers (as for other error types). However, if the other
    // servers are also busy, we're going to wait for a little while and then retry each server that
    // returned Busy in the previous round. If the server is still Busy, this continues, while
    // the backoff increases exponentially (by a factor of 2), until it hits 300ms, in which case we
    // give up. The request might still be retried by the caller (likely the DnsRetryHandle).
    //
    // TODO: more principled handling of timeouts. Currently, timeouts appear to be handled mostly
    // close to the connection, which means the top level resolution might take substantially longer
    // to fire than the timeout configured in `ResolverOpts`.
    let mut backoff = Duration::from_millis(20);
    let mut busy = SmallVec::<[NameServer<C, P>; 2]>::new();

    loop {
        let request_cont = request.clone();

        // construct the parallel requests, 2 is the default
        let mut par_conns = SmallVec::<[NameServer<C, P>; 2]>::new();
        let count = conns.len().min(opts.num_concurrent_reqs.max(1));
        for conn in conns.drain(..count) {
            par_conns.push(conn);
        }

        if par_conns.is_empty() {
            if !busy.is_empty() && backoff < Duration::from_millis(300) {
                P::Time::delay_for(backoff).await;
                conns.extend(busy.drain(..));
                backoff *= 2;
                continue;
            }
            return Err(err);
        }

        let mut requests = par_conns
            .into_iter()
            .map(move |mut conn| {
                conn.send(request_cont.clone())
                    .map(|result| result.map_err(|e| (conn, e)))
            })
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = requests.next().await {
            let (conn, e) = match result {
                Ok(sent) => return Ok(sent),
                Err((conn, e)) => (conn, e),
            };

            match e.kind() {
                ResolveErrorKind::NoRecordsFound { trusted, .. } if *trusted => {
                    return Err(e);
                }
                ResolveErrorKind::Proto(e) if e.is_busy() => {
                    busy.push(conn);
                }
                _ if err.cmp_specificity(&e) != Ordering::Greater => {
                    err = e;
                }
                _ => {}
            }
        }
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
        C: DnsHandle<Error = ResolveError> + 'static,
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
    ResolveFuture(Pin<Box<dyn Future<Output = Result<DnsResponse, ResolveError>> + Send>>),
    NotMdns(DnsRequest),
}

impl Local {
    fn is_local(&self) -> bool {
        matches!(*self, Local::ResolveFuture(..))
    }

    /// Takes the future
    ///
    /// # Panics
    ///
    /// Panics if this is in fact a Local::NotMdns
    fn take_future(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<DnsResponse, ResolveError>> + Send>> {
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
    type Output = Result<DnsResponse, ResolveError>;

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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;

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
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };

        let config2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };

        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let io_loop = Runtime::new().unwrap();
        let mut pool = NameServerPool::<_, TokioConnectionProvider>::from_config(
            &resolver_config,
            &ResolverOpts::default(),
            TokioHandle,
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

    #[test]
    fn test_multi_use_conns() {
        env_logger::try_init().ok();

        let io_loop = Runtime::new().unwrap();
        let conn_provider = TokioConnectionProvider::new(TokioHandle);

        let tcp = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
        };

        let opts = ResolverOpts::default();
        let ns_config = { tcp };
        let name_server = NameServer::new_with_provider(ns_config, opts, conn_provider.clone());
        let name_servers: Arc<[_]> = Arc::from([name_server]);

        let mut pool = NameServerPool::from_nameservers_test(
            &opts,
            Arc::from([]),
            Arc::clone(&name_servers),
            #[cfg(feature = "mdns")]
            name_server::mdns_nameserver(opts, conn_provider.clone(), false),
            conn_provider,
        );

        let name = Name::from_str("www.example.com.").unwrap();

        // first lookup
        let response = io_loop
            .block_on(pool.lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            ))
            .expect("lookup failed");

        assert_eq!(
            *response.answers()[0]
                .rdata()
                .as_a()
                .expect("no a record available"),
            Ipv4Addr::new(93, 184, 216, 34)
        );

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );

        // first lookup
        let response = io_loop
            .block_on(pool.lookup(
                Query::query(name, RecordType::AAAA),
                DnsRequestOptions::default(),
            ))
            .expect("lookup failed");

        assert_eq!(
            *response.answers()[0]
                .rdata()
                .as_aaaa()
                .expect("no aaaa record available"),
            Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946)
        );

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );
    }
}
