// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::time::Duration;

use futures_util::future::FutureExt;
use futures_util::stream::{FuturesUnordered, Stream, StreamExt, once};
use hickory_proto::NoRecords;
use hickory_proto::op::ResponseCode;
use smallvec::SmallVec;
use tracing::debug;

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy};
use crate::name_server::connection_provider::ConnectionProvider;
use crate::name_server::name_server::NameServer;
use crate::proto::runtime::{RuntimeProvider, Time};
use crate::proto::xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer, Protocol};
use crate::proto::{ProtoError, ProtoErrorKind};

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider> {
    state: Arc<PoolState<P>>,
}

impl<P: ConnectionProvider> NameServerPool<P> {
    pub(crate) fn from_config_with_provider(
        config: &ResolverConfig,
        options: Arc<ResolverOpts>,
        conn_provider: P,
    ) -> Self {
        let servers = config
            .name_servers()
            .iter()
            .map(|ns_config| {
                NameServer::new(ns_config.clone(), options.clone(), conn_provider.clone())
            })
            .collect();

        Self::from_nameservers(servers, options)
    }

    /// Construct a NameServerPool from a set of name server configs
    pub fn from_config(
        name_servers: Vec<NameServerConfig>,
        options: Arc<ResolverOpts>,
        conn_provider: P,
    ) -> Self {
        Self::from_nameservers(
            name_servers
                .into_iter()
                .map(|ns_config| NameServer::new(ns_config, options.clone(), conn_provider.clone()))
                .collect(),
            options,
        )
    }

    #[doc(hidden)]
    pub fn from_nameservers(servers: Vec<NameServer<P>>, options: Arc<ResolverOpts>) -> Self {
        Self {
            state: Arc::new(PoolState::new(servers, options)),
        }
    }

    /// Returns the pool's options.
    pub fn options(&self) -> &ResolverOpts {
        &self.state.options
    }
}

impl<P: ConnectionProvider> DnsHandle for NameServerPool<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let state = self.state.clone();
        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries());
            try_send(&state.options, &state.servers, request, &state.next).await
        }))
    }
}

struct PoolState<P: ConnectionProvider> {
    servers: Vec<NameServer<P>>,
    options: Arc<ResolverOpts>,
    next: AtomicUsize,
}

impl<P: ConnectionProvider> PoolState<P> {
    fn new(mut servers: Vec<NameServer<P>>, options: Arc<ResolverOpts>) -> Self {
        // Unless the user specified that we should follow the configured order,
        // re-order the servers to prioritize UDP.
        if options.server_ordering_strategy != ServerOrderingStrategy::UserProvidedOrder {
            servers.sort_by_key(|ns| (ns.protocol() != Protocol::Udp) as u8);
        }

        Self {
            servers,
            options,
            next: AtomicUsize::new(0),
        }
    }
}

async fn try_send<P: ConnectionProvider>(
    opts: &ResolverOpts,
    conns: &[NameServer<P>],
    request: DnsRequest,
    next_index: &AtomicUsize,
) -> Result<DnsResponse, ProtoError> {
    let mut conns: Vec<NameServer<P>> = conns.to_vec();

    match opts.server_ordering_strategy {
        // select the highest priority connection
        //   reorder the connections based on current view...
        //   this reorders the inner set
        ServerOrderingStrategy::QueryStatistics => {
            conns.sort_by(|a, b| match (a.protocol(), b.protocol()) {
                (ap, bp) if ap == bp => a.decayed_srtt().total_cmp(&b.decayed_srtt()),
                (Protocol::Udp, _) => Ordering::Less,
                (_, Protocol::Udp) => Ordering::Greater,
                (_, _) => a.decayed_srtt().total_cmp(&b.decayed_srtt()),
            });
        }
        ServerOrderingStrategy::UserProvidedOrder => {}
        ServerOrderingStrategy::RoundRobin => {
            let num_concurrent_reqs = if opts.num_concurrent_reqs > 1 {
                opts.num_concurrent_reqs
            } else {
                1
            };
            if num_concurrent_reqs < conns.len() {
                let index =
                    next_index.fetch_add(num_concurrent_reqs, AtomicOrdering::SeqCst) % conns.len();
                conns.rotate_left(index);
            }
        }
    }

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
    let mut conns = VecDeque::from(conns);
    let mut backoff = Duration::from_millis(20);
    let mut busy = SmallVec::<[NameServer<P>; 2]>::new();
    let mut err = ProtoError::from(ProtoErrorKind::NoConnections);
    let mut skip_udp = false;

    loop {
        // construct the parallel requests, 2 is the default
        let mut par_conns = SmallVec::<[NameServer<P>; 2]>::new();
        while !conns.is_empty() && par_conns.len() < Ord::max(opts.num_concurrent_reqs, 1) {
            if let Some(conn) = conns.pop_front() {
                if !(skip_udp && conn.protocol() == Protocol::Udp) {
                    par_conns.push(conn);
                }
            }
        }

        if par_conns.is_empty() {
            if !busy.is_empty() && backoff < Duration::from_millis(300) {
                <<P as ConnectionProvider>::RuntimeProvider as RuntimeProvider>::Timer::delay_for(
                    backoff,
                )
                .await;
                conns.extend(
                    busy.drain(..)
                        .filter(|ns| !(skip_udp && ns.protocol() == Protocol::Udp)),
                );
                backoff *= 2;
                continue;
            }
            return Err(err);
        }

        let mut requests = par_conns
            .into_iter()
            .map(|conn| {
                conn.send(request.clone())
                    .first_answer()
                    .map(|result| result.map_err(|e| (conn, e)))
            })
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = requests.next().await {
            let (conn, e) = match result {
                Ok(response) if response.truncated() => {
                    debug!("truncated response received, retrying over TCP");
                    skip_udp = true;
                    err = ProtoError::from("received truncated response");
                    continue;
                }
                Ok(response) => return Ok(response),
                Err((conn, e)) => (conn, e),
            };

            use ProtoErrorKind::*;
            match e.kind() {
                // We assume the response is spoofed, so ignore it and avoid UDP server for this
                // request to try and avoid further spoofing.
                QueryCaseMismatch => skip_udp = true,
                // If the server is busy, try it again later if necessary.
                Busy => busy.push(conn),
                // If the connection failed, try another one.
                Io(_) | NoConnections => {}
                // If we got an `NXDomain` response from a server whose negative responses we
                // don't trust, we should try another server.
                NoRecordsFound(NoRecords {
                    response_code: ResponseCode::NXDomain,
                    ..
                }) if !conn.trust_negative_responses() => {}
                _ => return Err(e),
            }

            if err.cmp_specificity(&e) == Ordering::Less {
                err = e;
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;

    use test_support::subscribe;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::config::{NameServerConfig, ProtocolConfig};
    use crate::proto::op::Query;
    use crate::proto::rr::{Name, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::xfer::{DnsHandle, DnsRequestOptions};

    #[ignore]
    // because of there is a real connection that needs a reasonable timeout
    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_failed_then_success_pool() {
        subscribe();

        let config1 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 253),
            protocol: ProtocolConfig::Udp,
            trust_negative_responses: false,
            bind_addr: None,
        };

        let config2 = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: ProtocolConfig::Udp,
            trust_negative_responses: false,
            bind_addr: None,
        };

        let mut resolver_config = ResolverConfig::default();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let io_loop = Runtime::new().unwrap();
        let pool = NameServerPool::tokio_from_config(
            &resolver_config,
            Arc::new(ResolverOpts::default()),
            TokioRuntimeProvider::new(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();

        // TODO: it's not clear why there are two failures before the success
        for i in 0..2 {
            assert!(
                io_loop
                    .block_on(
                        pool.lookup(
                            Query::query(name.clone(), RecordType::A),
                            DnsRequestOptions::default()
                        )
                        .first_answer()
                    )
                    .is_err(),
                "iter: {}",
                i
            );
        }

        for i in 0..10 {
            assert!(
                io_loop
                    .block_on(
                        pool.lookup(
                            Query::query(name.clone(), RecordType::A),
                            DnsRequestOptions::default()
                        )
                        .first_answer()
                    )
                    .is_ok(),
                "iter: {}",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_multi_use_conns() {
        subscribe();

        let conn_provider = TokioRuntimeProvider::default();

        let tcp = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: ProtocolConfig::Tcp,
            trust_negative_responses: false,
            bind_addr: None,
        };

        let opts = Arc::new(ResolverOpts {
            try_tcp_on_error: true,
            ..ResolverOpts::default()
        });
        let name_server = NameServer::new(tcp, opts.clone(), conn_provider);
        let name_servers = vec![name_server];
        let pool = NameServerPool::from_nameservers(name_servers.clone(), opts);

        let name = Name::from_str("www.example.com.").unwrap();

        // first lookup
        let response = pool
            .lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("lookup failed");

        assert!(!response.answers().is_empty());

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );

        // first lookup
        let response = pool
            .lookup(
                Query::query(name, RecordType::AAAA),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("lookup failed");

        assert!(!response.answers().is_empty());

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );
    }

    impl NameServerPool<TokioRuntimeProvider> {
        pub(crate) fn tokio_from_config(
            config: &ResolverConfig,
            options: Arc<ResolverOpts>,
            provider: TokioRuntimeProvider,
        ) -> Self {
            Self::from_config_with_provider(config, options, provider)
        }
    }
}
