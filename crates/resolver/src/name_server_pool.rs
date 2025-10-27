// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU8;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::lock::{Mutex as AsyncMutex, MutexGuard};
use futures_util::stream::{FuturesUnordered, Stream, StreamExt, once};
use futures_util::{
    Future, FutureExt,
    future::{BoxFuture, Shared},
};
use hickory_proto::{serialize::binary::BinEncodable, xfer::Protocol};
use parking_lot::Mutex;
use smallvec::SmallVec;
use tracing::{debug, error, info};

#[cfg(any(feature = "__tls", feature = "__quic"))]
use crate::config::OpportunisticEncryptionConfig;
use crate::config::{
    NameServerConfig, OpportunisticEncryption, ResolverOpts, ServerOrderingStrategy,
};
use crate::connection_provider::{ConnectionProvider, TlsConfig};
use crate::name_server::{ConnectionPolicy, NameServer};
use crate::proto::{
    DnsError, NoRecords, ProtoError, ProtoErrorKind,
    access_control::AccessControlSet,
    op::{DnsRequest, DnsRequestOptions, DnsResponse, Query, ResponseCode},
    rr::{
        RData, Record,
        rdata::{A, AAAA},
    },
    runtime::{RuntimeProvider, Time},
    xfer::DnsHandle,
};

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider> {
    state: Arc<PoolState<P>>,
    active_requests: Arc<Mutex<HashMap<Arc<Vec<u8>>, SharedLookup>>>,
}

#[derive(Clone)]
pub(crate) struct SharedLookup(Shared<BoxFuture<'static, Option<Result<DnsResponse, ProtoError>>>>);

impl Future for SharedLookup {
    type Output = Result<DnsResponse, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx).map(|o| match o {
            Some(r) => r,
            None => Err("no response from nameserver".into()),
        })
    }
}

impl<P: ConnectionProvider> NameServerPool<P> {
    /// Construct a NameServerPool from a set of name server configs
    pub fn from_config(
        servers: impl IntoIterator<Item = NameServerConfig>,
        cx: Arc<PoolContext>,
        opportunistic_probe_budget: Arc<AtomicU8>,
        conn_provider: P,
    ) -> Self {
        Self::from_nameservers(
            servers
                .into_iter()
                .map(|server| {
                    Arc::new(NameServer::new(
                        [],
                        server,
                        &cx.options,
                        opportunistic_probe_budget.clone(),
                        conn_provider.clone(),
                    ))
                })
                .collect(),
            cx,
        )
    }

    #[doc(hidden)]
    pub fn from_nameservers(servers: Vec<Arc<NameServer<P>>>, cx: Arc<PoolContext>) -> Self {
        Self {
            state: Arc::new(PoolState {
                servers,
                cx,
                next: AtomicUsize::new(0),
            }),
            active_requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the pool's options.
    pub fn context(&self) -> &Arc<PoolContext> {
        &self.state.cx
    }
}

impl<P: ConnectionProvider> DnsHandle for NameServerPool<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;
    type Runtime = P::RuntimeProvider;

    fn lookup(&self, query: Query, mut options: DnsRequestOptions) -> Self::Response {
        debug!("querying: {} {:?}", query.name(), query.query_type());
        options.case_randomization = self.state.cx.options.case_randomization;
        self.send(DnsRequest::from_query(query, options))
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        let state = self.state.clone();
        let acs = self.state.cx.answer_address_filter.clone();
        let active_requests = self.active_requests.clone();

        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries());
            let query = match request.queries().first() {
                Some(q) => q.clone(),
                None => return Err("no query in request".into()),
            };

            // Save and zero the transaction id so otherwise identical requests will hash identically
            let tx_id = request.id();
            request.set_id(0);
            let key = Arc::new(request.to_bytes()?);

            let lookup = {
                let mut active = active_requests.lock();
                if let Some(existing) = active.get(&key) {
                    debug!(%query, "query currently in progress - returning shared lookup");
                    existing.clone()
                } else {
                    info!(%query, "creating new shared lookup");

                    let lookup = async move {
                        request.set_id(tx_id);
                        match state.try_send(request).await {
                            Ok(response) => Some(Ok(response)),
                            Err(e) => Some(Err(e)),
                        }
                    }
                    .boxed()
                    .shared();

                    let shared_lookup = SharedLookup(lookup);
                    active.insert(key.clone(), shared_lookup.clone());
                    shared_lookup
                }
            };

            let response = lookup.await;

            // remove the concurrent request marker
            active_requests.lock().remove(&key);
            let mut response = response?;

            let Some(acs) = acs else {
                return Ok(response);
            };

            let answer_filter = |record: &Record| {
                let ip = match record.data() {
                    RData::A(A(ipv4)) => (*ipv4).into(),
                    RData::AAAA(AAAA(ipv6)) => (*ipv6).into(),
                    _ => return true,
                };

                if acs.denied(ip) {
                    error!(
                        %query,
                        %ip,
                        "removing ip from response: answer filter matched"
                    );

                    false
                } else {
                    true
                }
            };

            let answers_len = response.answers().len();
            let authorities_len = response.authorities().len();

            response.additionals_mut().retain(answer_filter);
            response.answers_mut().retain(answer_filter);
            response.authorities_mut().retain(answer_filter);

            if response.answers().is_empty() && answers_len != 0
                || (response.answers().is_empty()
                    && response.authorities().is_empty()
                    && authorities_len != 0)
            {
                return Err(NoRecords::new(Box::new(query.clone()), ResponseCode::NXDomain).into());
            }

            // Since the message might have changed, create a new response from
            // the message to update the buffer.
            DnsResponse::from_message(response.into_message())
        }))
    }
}

struct PoolState<P: ConnectionProvider> {
    servers: Vec<Arc<NameServer<P>>>,
    cx: Arc<PoolContext>,
    next: AtomicUsize,
}

impl<P: ConnectionProvider> PoolState<P> {
    async fn try_send(&self, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
        let mut servers = self.servers.clone();
        match self.cx.options.server_ordering_strategy {
            // select the highest priority connection
            //   reorder the connections based on current view...
            //   this reorders the inner set
            ServerOrderingStrategy::QueryStatistics => {
                servers.sort_by(|a, b| a.decayed_srtt().total_cmp(&b.decayed_srtt()));
            }
            ServerOrderingStrategy::UserProvidedOrder => {}
            ServerOrderingStrategy::RoundRobin => {
                let num_concurrent_reqs = if self.cx.options.num_concurrent_reqs > 1 {
                    self.cx.options.num_concurrent_reqs
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
        let mut policy = ConnectionPolicy::default();

        loop {
            // construct the parallel requests, 2 is the default
            let mut par_servers = SmallVec::<[_; 2]>::new();
            while !servers.is_empty()
                && par_servers.len() < Ord::max(self.cx.options.num_concurrent_reqs, 1)
            {
                if let Some(server) = servers.pop_front() {
                    if policy.allows_server(&server) {
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
                    servers.extend(busy.drain(..).filter(|ns| policy.allows_server(ns)));
                    backoff *= 2;
                    continue;
                }
                return Err(err);
            }

            let mut requests = par_servers
                .into_iter()
                .map(|server| {
                    let future = server.clone().send(request.clone(), policy, &self.cx);
                    async { (server, future.await) }
                })
                .collect::<FuturesUnordered<_>>();

            while let Some((server, result)) = requests.next().await {
                let e = match result {
                    Ok(response) if response.truncated() => {
                        debug!("truncated response received, retrying over TCP");
                        policy.disable_udp = true;
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
                        policy.disable_udp = true;
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

/// Context for a [`NameServerPool`]
#[non_exhaustive]
pub struct PoolContext {
    /// Resolver options
    pub options: ResolverOpts,
    /// TLS configuration
    pub tls: TlsConfig,
    /// Opportunistic encryption configuration
    pub opportunistic_encryption: OpportunisticEncryption,
    pub(crate) transport_state: AsyncMutex<NameServerTransportState>,
    /// Answer address filter
    pub answer_address_filter: Option<AccessControlSet>,
}

impl PoolContext {
    /// Creates a new PoolContext
    pub fn new(options: ResolverOpts, tls: TlsConfig) -> Self {
        Self {
            answer_address_filter: options.answer_address_filter(),
            options,
            tls,
            opportunistic_encryption: OpportunisticEncryption::default(),
            transport_state: AsyncMutex::new(NameServerTransportState::default()),
        }
    }

    /// Add an answer address filter
    pub fn with_answer_filter(mut self, answer_filter: AccessControlSet) -> Self {
        self.answer_address_filter = Some(answer_filter);
        self
    }

    /// Enables opportunistic encryption with default configuration
    #[cfg(any(feature = "__tls", feature = "__quic"))]
    pub fn with_opportunistic_encryption(mut self) -> Self {
        self.opportunistic_encryption = OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };
        self
    }

    /// Sets the transport state
    pub fn with_transport_state(mut self, transport_state: NameServerTransportState) -> Self {
        self.transport_state = AsyncMutex::new(transport_state);
        self
    }

    pub(crate) async fn transport_state(&self) -> MutexGuard<'_, NameServerTransportState> {
        self.transport_state.lock().await
    }
}

/// A mapping from nameserver IP address and protocol to encrypted transport state.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct NameServerTransportState(HashMap<(IpAddr, Protocol), TransportState>);

impl NameServerTransportState {
    /// Update the transport state for the given IP and protocol to record a connection initiation.
    pub(crate) fn initiate_connection(&mut self, ip: IpAddr, protocol: Protocol) {
        self.0.insert((ip, protocol), TransportState::default());
    }

    /// Update the transport state for the given IP and protocol to record a connection completion.
    pub(crate) fn complete_connection(&mut self, ip: IpAddr, protocol: Protocol) {
        self.0.insert(
            (ip, protocol),
            TransportState::Success {
                last_response: None,
            },
        );
    }

    /// Update the successful transport state for the given IP and protocol to record a response received.
    pub(crate) fn response_received(&mut self, ip: IpAddr, protocol: Protocol) {
        let Some(TransportState::Success { last_response, .. }) = self.0.get_mut(&(ip, protocol))
        else {
            return;
        };
        *last_response = Some(Instant::now());
    }

    /// Update the transport state for the given IP and protocol to record a received error.
    pub(crate) fn error_received(&mut self, ip: IpAddr, protocol: Protocol, error: &ProtoError) {
        self.0.insert(
            (ip, protocol),
            match error.kind() {
                ProtoErrorKind::Timeout => TransportState::TimedOut {
                    #[cfg(any(feature = "__tls", feature = "__quic"))]
                    completed_at: Instant::now(),
                },
                _ => TransportState::Failed {
                    #[cfg(any(feature = "__tls", feature = "__quic"))]
                    completed_at: Instant::now(),
                },
            },
        );
    }

    /// Returns true if any supported encrypted protocol had a recent success for the given IP
    /// within the damping period.
    #[cfg(any(feature = "__tls", feature = "__quic"))]
    pub(crate) fn any_recent_success(&self, ip: IpAddr, config: &OpportunisticEncryption) -> bool {
        #[allow(unused_assignments, unused_mut)]
        let mut tls_success = false;
        #[allow(unused_assignments, unused_mut)]
        let mut quic_success = false;

        #[cfg(feature = "__tls")]
        {
            tls_success = self.recent_success(ip, Protocol::Tls, config);
        }

        #[cfg(feature = "__quic")]
        {
            quic_success = self.recent_success(ip, Protocol::Quic, config);
        }

        tls_success || quic_success
    }

    /// Returns true if any encrypted protocol had a recent success for the given IP within the damping period.
    #[cfg(not(any(feature = "__tls", feature = "__quic")))]
    pub(crate) fn any_recent_success(
        &self,
        _ip: IpAddr,
        _config: &OpportunisticEncryption,
    ) -> bool {
        false
    }

    /// Returns true if there has been a successful response within the persistence period for the
    /// IP/protocol.
    ///
    /// Returns false if opportunistic encryption is disabled, or if there has not been a successful
    /// response read.
    #[cfg(any(feature = "__tls", feature = "__quic"))]
    pub(crate) fn recent_success(
        &self,
        ip: IpAddr,
        protocol: Protocol,
        config: &OpportunisticEncryption,
    ) -> bool {
        let OpportunisticEncryption::Enabled { config } = config else {
            return false;
        };

        let Some(TransportState::Success { last_response, .. }) = self.0.get(&(ip, protocol))
        else {
            return false;
        };

        let Some(last_response) = last_response else {
            return false;
        };

        Instant::now().duration_since(*last_response) <= config.persistence_period
    }

    /// Returns true if there has been a successful response within the persistence period.
    ///
    /// Returns false if opportunistic encryption is disabled, or if there has not been a successful
    /// response read.
    #[cfg(not(any(feature = "__tls", feature = "__quic")))]
    pub(crate) fn recent_success(
        &self,
        _ip: IpAddr,
        _protocol: Protocol,
        _config: &OpportunisticEncryption,
    ) -> bool {
        false
    }

    /// Returns true if we should probe encrypted transport based on RFC 9539 damping logic.
    #[cfg(any(feature = "__tls", feature = "__quic"))]
    pub(crate) fn should_probe_encrypted(
        &self,
        ip: IpAddr,
        protocol: Protocol,
        config: &OpportunisticEncryption,
    ) -> bool {
        debug_assert!(protocol.is_encrypted());

        let OpportunisticEncryption::Enabled { config, .. } = config else {
            return false;
        };

        let Some(state) = self.0.get(&(ip, protocol)) else {
            return true;
        };

        match state {
            TransportState::Initiated => false,
            TransportState::Success { .. } => true,
            TransportState::Failed { completed_at } | TransportState::TimedOut { completed_at } => {
                completed_at.elapsed() > config.damping_period
            }
        }
    }

    /// Returns true if we should probe encrypted transport based on RFC 9539 damping logic.
    #[cfg(not(any(feature = "__tls", feature = "__quic")))]
    pub(crate) fn should_probe_encrypted(
        &self,
        _ip: IpAddr,
        _protocol: Protocol,
        _config: &OpportunisticEncryption,
    ) -> bool {
        false
    }

    /// For testing, set the last response time for successful connections to the ip/protocol.
    #[cfg(all(test, feature = "__tls"))]
    pub(crate) fn set_last_response(&mut self, ip: IpAddr, protocol: Protocol, when: Instant) {
        let Some(TransportState::Success { last_response, .. }) = self.0.get_mut(&(ip, protocol))
        else {
            return;
        };

        *last_response = Some(when);
    }

    /// For testing, set the completion time for failed connections to the ip/protocol.
    #[cfg(all(test, feature = "__tls"))]
    pub(crate) fn set_failure_time(&mut self, ip: IpAddr, protocol: Protocol, when: Instant) {
        self.0.insert(
            (ip, protocol),
            TransportState::Failed { completed_at: when },
        );
    }
}

/// State tracked per nameserver IP/protocol to inform opportunistic encryption.
#[derive(Debug, Clone, Copy, Default)]
enum TransportState {
    /// Connection attempt has been initiated.
    #[default]
    Initiated,
    /// Connection completed successfully.
    Success {
        /// The last instant at which a response was read on the connection (if any).
        last_response: Option<Instant>,
    },
    /// Connection failed with an error.
    Failed {
        /// The instant the connection attempt was completed at.
        #[cfg(any(feature = "__tls", feature = "__quic"))]
        completed_at: Instant,
    },
    /// Connection timed out.
    TimedOut {
        /// The instant the connection attempt was completed at.
        #[cfg(any(feature = "__tls", feature = "__quic"))]
        completed_at: Instant,
    },
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::{
        net::IpAddr,
        str::FromStr,
        sync::atomic::{AtomicU8, Ordering},
        thread::sleep,
    };

    use test_support::{MockNetworkHandler, MockProvider, MockRecord, ProtocolConfig, subscribe};
    use tokio::runtime::Runtime;

    use super::*;
    use crate::config::{NameServerConfig, ResolverConfig};
    use crate::proto::op::{DnsRequestOptions, Message, Query};
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
            Arc::new(PoolContext::new(
                ResolverOpts::default(),
                TlsConfig::new().unwrap(),
            )),
            Arc::new(AtomicU8::default()),
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
        let opts = ResolverOpts {
            try_tcp_on_error: true,
            ..ResolverOpts::default()
        };

        let tcp = NameServerConfig::tcp(IpAddr::from([8, 8, 8, 8]));
        let name_server = Arc::new(NameServer::new(
            [],
            tcp,
            &opts,
            Arc::new(AtomicU8::default()),
            conn_provider,
        ));
        let name_servers = vec![name_server];
        let pool = NameServerPool::from_nameservers(
            name_servers.clone(),
            Arc::new(PoolContext::new(opts, TlsConfig::new().unwrap())),
        );

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

    #[tokio::test]
    async fn test_shared_lookup() -> Result<(), ProtoError> {
        subscribe();

        let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
        let query_ip = IpAddr::from([10, 0, 0, 1]);

        let responses = vec![MockRecord::a(query_ip, &query_name, query_ip)];

        let counter = Arc::new(AtomicU8::new(0));
        let counter_copy = counter.clone();
        let mutator = Box::new(
            move |_destination: IpAddr, _protocol: ProtocolConfig, _msg: &mut Message| {
                counter_copy.fetch_add(1, Ordering::Relaxed);
                // Ensure the first query is still active when the second is polled
                sleep(Duration::from_millis(250));
            },
        );

        let handler = MockNetworkHandler::new(responses).with_mutation(mutator);

        let provider = MockProvider::new(handler);
        let opts = ResolverOpts::default();
        let name_server = Arc::new(NameServer::new(
            [],
            NameServerConfig::udp(query_ip),
            &opts,
            Arc::new(AtomicU8::default()),
            provider,
        ));
        let pool = NameServerPool::from_nameservers(
            vec![name_server],
            Arc::new(PoolContext::new(opts, TlsConfig::new().unwrap())),
        );

        let mut futures = vec![
            pool.lookup(
                Query::query(query_name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer(),
            pool.lookup(
                Query::query(query_name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer(),
        ]
        .into_iter()
        .collect::<FuturesUnordered<_>>();

        let mut ok_count = 0;
        while let Some(Ok(response)) = futures.next().await {
            assert_eq!(response.response_code(), ResponseCode::NoError);
            ok_count += 1;
        }

        assert_eq!(ok_count, 2);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        Ok(())
    }
}
