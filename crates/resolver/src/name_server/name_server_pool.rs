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

use futures_util::stream::{FuturesUnordered, Stream, StreamExt, once};
use smallvec::SmallVec;
use tracing::debug;

use crate::config::{NameServerConfig, ResolverOpts, ServerOrderingStrategy};
use crate::name_server::connection_provider::{ConnectionProvider, TlsConfig};
use crate::name_server::name_server::{NameServer, Preferences};
use crate::proto::op::{DnsRequest, DnsResponse, ResponseCode};
use crate::proto::runtime::{RuntimeProvider, Time};
use crate::proto::xfer::DnsHandle;
use crate::proto::{DnsError, NoRecords, ProtoError, ProtoErrorKind};

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider> {
    state: Arc<PoolState<P>>,
}

impl<P: ConnectionProvider> NameServerPool<P> {
    /// Construct a NameServerPool from a set of name server configs
    pub fn from_config(
        servers: impl IntoIterator<Item = NameServerConfig>,
        options: Arc<ResolverOpts>,
        tls: Arc<TlsConfig>,
        conn_provider: P,
    ) -> Self {
        Self::from_nameservers(
            servers
                .into_iter()
                .map(|server| {
                    Arc::new(NameServer::new(
                        [],
                        server,
                        options.clone(),
                        tls.clone(),
                        conn_provider.clone(),
                    ))
                })
                .collect(),
            options,
        )
    }

    #[doc(hidden)]
    pub fn from_nameservers(servers: Vec<Arc<NameServer<P>>>, options: Arc<ResolverOpts>) -> Self {
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
    type Runtime = P::RuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let state = self.state.clone();
        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries());
            state.try_send(request).await
        }))
    }
}

struct PoolState<P: ConnectionProvider> {
    servers: Vec<Arc<NameServer<P>>>,
    options: Arc<ResolverOpts>,
    next: AtomicUsize,
}

impl<P: ConnectionProvider> PoolState<P> {
    fn new(servers: Vec<Arc<NameServer<P>>>, options: Arc<ResolverOpts>) -> Self {
        Self {
            servers,
            options,
            next: AtomicUsize::new(0),
        }
    }

    async fn try_send(&self, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
        let mut servers = self.servers.clone();
        match self.options.server_ordering_strategy {
            // select the highest priority connection
            //   reorder the connections based on current view...
            //   this reorders the inner set
            ServerOrderingStrategy::QueryStatistics => {
                servers.sort_by(|a, b| a.decayed_srtt().total_cmp(&b.decayed_srtt()));
            }
            ServerOrderingStrategy::UserProvidedOrder => {}
            ServerOrderingStrategy::RoundRobin => {
                let num_concurrent_reqs = if self.options.num_concurrent_reqs > 1 {
                    self.options.num_concurrent_reqs
                } else {
                    1
                };
                if num_concurrent_reqs < servers.len() {
                    let index = self
                        .next
                        .fetch_add(num_concurrent_reqs, AtomicOrdering::SeqCst)
                        % servers.len();
                    servers.rotate_left(index);
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
        let mut servers = VecDeque::from(servers);
        let mut backoff = Duration::from_millis(20);
        let mut busy = SmallVec::<[Arc<NameServer<P>>; 2]>::new();
        let mut err = ProtoError::from(ProtoErrorKind::NoConnections);
        let mut preferences = Preferences::default();

        loop {
            // construct the parallel requests, 2 is the default
            let mut par_servers = SmallVec::<[_; 2]>::new();
            while !servers.is_empty()
                && par_servers.len() < Ord::max(self.options.num_concurrent_reqs, 1)
            {
                if let Some(server) = servers.pop_front() {
                    if preferences.allows_server(&server) {
                        par_servers.push(server);
                    }
                }
            }

            if par_servers.is_empty() {
                if !busy.is_empty() && backoff < Duration::from_millis(300) {
                    <<P as ConnectionProvider>::RuntimeProvider as RuntimeProvider>::Timer::delay_for(
                    backoff,
                )
                .await;
                    servers.extend(busy.drain(..).filter(|ns| preferences.allows_server(ns)));
                    backoff *= 2;
                    continue;
                }
                return Err(err);
            }

            let mut requests = par_servers
                .into_iter()
                .map(|server| {
                    let future = server.clone().send(request.clone(), preferences);
                    async { (server, future.await) }
                })
                .collect::<FuturesUnordered<_>>();

            while let Some((server, result)) = requests.next().await {
                let e = match result {
                    Ok(response) if response.truncated() => {
                        debug!("truncated response received, retrying over TCP");
                        preferences.exclude_udp = true;
                        err = ProtoError::from("received truncated response");
                        servers.push_front(server);
                        continue;
                    }
                    Ok(response) => return Ok(response),
                    Err(e) => e,
                };

                match e.kind() {
                    // We assume the response is spoofed, so ignore it and avoid UDP server for this
                    // request to try and avoid further spoofing.
                    ProtoErrorKind::QueryCaseMismatch => {
                        servers.push_front(server);
                        preferences.exclude_udp = true;
                        continue;
                    }
                    // If the server is busy, try it again later if necessary.
                    ProtoErrorKind::Busy => busy.push(server),
                    // If the connection failed, try another one.
                    ProtoErrorKind::Io(_) | ProtoErrorKind::NoConnections => {}
                    // If we got an `NXDomain` response from a server whose negative responses we
                    // don't trust, we should try another server.
                    ProtoErrorKind::Dns(DnsError::NoRecordsFound(NoRecords {
                        response_code: ResponseCode::NXDomain,
                        ..
                    })) if !server.trust_negative_responses() => {}
                    _ => return Err(e),
                }

                if err.cmp_specificity(&e) == Ordering::Less {
                    err = e;
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use test_support::subscribe;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::config::{NameServerConfig, ResolverConfig};
    use crate::proto::op::{DnsRequestOptions, Query};
    use crate::proto::rr::{Name, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::xfer::{DnsHandle, FirstAnswer};

    #[ignore]
    // because of there is a real connection that needs a reasonable timeout
    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_failed_then_success_pool() {
        subscribe();

        let mut config1 = NameServerConfig::udp(IpAddr::from([127, 0, 0, 252]));
        config1.trust_negative_responses = false;
        let config2 = NameServerConfig::udp(IpAddr::from([8, 8, 8, 8]));

        let mut resolver_config = ResolverConfig::default();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let io_loop = Runtime::new().unwrap();
        let pool = NameServerPool::from_config(
            resolver_config.name_servers,
            Arc::new(ResolverOpts::default()),
            Arc::new(TlsConfig::new().unwrap()),
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
        let opts = Arc::new(ResolverOpts {
            try_tcp_on_error: true,
            ..ResolverOpts::default()
        });

        let tcp = NameServerConfig::tcp(IpAddr::from([8, 8, 8, 8]));
        let name_server = Arc::new(NameServer::new(
            [],
            tcp,
            opts.clone(),
            Arc::new(TlsConfig::new().unwrap()),
            conn_provider,
        ));
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
}
