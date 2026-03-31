// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU8;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use futures_util::lock::{Mutex as AsyncMutex, MutexGuard};
use futures_util::stream::{FuturesUnordered, Stream, StreamExt, once};
use futures_util::{
    Future, FutureExt,
    future::{BoxFuture, Shared},
};
use parking_lot::Mutex;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
#[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
use tracing::info;
use tracing::{debug, error};

#[cfg(any(feature = "__tls", feature = "__quic"))]
use crate::config::OpportunisticEncryptionConfig;
use crate::{
    config::{NameServerConfig, OpportunisticEncryption, ResolverOpts, ServerOrderingStrategy},
    connection_provider::{ConnectionProvider, TlsConfig},
    name_server::{ConnectionPolicy, NameServer},
    net::{
        DnsError, NetError, NoRecords,
        runtime::{RuntimeProvider, Time},
        xfer::{DnsHandle, Protocol},
    },
    proto::{
        access_control::AccessControlSet,
        op::{DnsRequest, DnsRequestOptions, DnsResponse, OpCode, Query, ResponseCode},
        rr::{
            Name, RData, Record,
            rdata::{
                A, AAAA,
                opt::{ClientSubnet, EdnsCode, EdnsOption},
            },
        },
    },
};

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider> {
    state: Arc<PoolState<P>>,
    active_requests: Arc<Mutex<HashMap<Arc<CacheKey>, SharedLookup>>>,
    ttl: Option<TtlInstant>,
    zone: Option<Name>,
}

impl<P: ConnectionProvider> NameServerPool<P> {
    /// Construct a NameServerPool from a set of name server configs
    pub fn from_config(
        servers: impl IntoIterator<Item = NameServerConfig>,
        cx: Arc<PoolContext>,
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
            ttl: None,
            zone: None,
        }
    }

    /// Set a TTL on the NameServerPool
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(TtlInstant::now() + ttl);
        self
    }

    /// Set the zone on the NameServerPool
    pub fn with_zone(mut self, zone: Name) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Check if the TTL on the NameServerPool (if set) has expired
    pub fn ttl_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => TtlInstant::now() > ttl,
            None => false,
        }
    }

    /// Returns the pool's options.
    pub fn context(&self) -> &Arc<PoolContext> {
        &self.state.cx
    }

    /// Return the zone associated with the pool
    pub fn zone(&self) -> Option<&Name> {
        self.zone.as_ref()
    }
}

// Type alias for TTL unit tests to use tokio's time pause/advance
#[cfg(not(feature = "tokio"))]
type TtlInstant = std::time::Instant;
#[cfg(feature = "tokio")]
type TtlInstant = tokio::time::Instant;

impl<P: ConnectionProvider> DnsHandle for NameServerPool<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = P::RuntimeProvider;

    fn lookup(&self, query: Query, mut options: DnsRequestOptions) -> Self::Response {
        debug!("querying: {} {:?}", query.name, query.query_type);
        options.case_randomization = self.state.cx.options.case_randomization;
        self.send(DnsRequest::from_query(query, options))
    }

    fn send(&self, request: DnsRequest) -> Self::Response {
        let state = self.state.clone();
        let acs = self.state.cx.answer_address_filter.clone();
        let active_requests = self.active_requests.clone();

        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries);
            let query = match request.queries.first() {
                Some(q) => q.clone(),
                None => return Err("no query in request".into()),
            };

            let key = Arc::new(CacheKey::from_request(&request));

            let (lookup, is_creator) = {
                let mut active = active_requests.lock();
                if let Some(existing) = active.get(&key) {
                    debug!(%query, "query currently in progress - returning shared lookup");
                    (existing.clone(), false)
                } else {
                    debug!(%query, "creating new shared lookup");

                    let lookup = async move {
                        match state.try_send(request).await {
                            Ok(response) => Some(Ok(response)),
                            Err(e) => Some(Err(e)),
                        }
                    }
                    .boxed()
                    .shared();

                    let shared_lookup = SharedLookup(lookup);
                    active.insert(key.clone(), shared_lookup.clone());
                    (shared_lookup, true)
                }
            };

            // Only the creator removes the key so that the entry is not
            // removed prematurely by a waiter task.  Using a guard ensures
            // the entry is removed even if `lookup.await` panics, which
            // would otherwise leave a poisoned `SharedLookup` in the map and
            // cause every subsequent request for the same key to also panic.
            let _cleanup = is_creator.then(|| ActiveRequestCleanup {
                active_requests: active_requests.clone(),
                key: key.clone(),
            });

            let response = lookup.await;
            let mut response = response?;

            if acs.allows_all() {
                return Ok(response);
            }

            let answer_filter = |record: &Record| {
                let ip = match &record.data {
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

            let answers_len = response.answers.len();
            let authorities_len = response.authorities.len();

            response.additionals.retain(answer_filter);
            response.answers.retain(answer_filter);
            response.authorities.retain(answer_filter);

            if response.answers.is_empty() && answers_len != 0
                || (response.answers.is_empty()
                    && response.authorities.is_empty()
                    && authorities_len != 0)
            {
                return Err(NoRecords::new(Box::new(query.clone()), ResponseCode::NXDomain).into());
            }

            // Since the message might have changed, create a new response from
            // the message to update the buffer.
            DnsResponse::from_message(response.into_message()).map_err(NetError::from)
        }))
    }
}

struct PoolState<P: ConnectionProvider> {
    servers: Vec<Arc<NameServer<P>>>,
    cx: Arc<PoolContext>,
    next: AtomicUsize,
}

impl<P: ConnectionProvider> PoolState<P> {
    async fn try_send(&self, request: DnsRequest) -> Result<DnsResponse, NetError> {
        let mut servers = self.servers.clone();
        match self.cx.options.server_ordering_strategy {
            // select the highest priority connection
            //   reorder the connections based on current view...
            //   this reorders the inner set
            ServerOrderingStrategy::QueryStatistics => {
                sort_servers_by_query_statistics(&mut servers);
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

        // If the name server we're trying is giving us backpressure by returning NetErrorKind::Busy,
        // we will first try the other name servers (as for other error types). However, if the other
        // servers are also busy, we're going to wait for a little while and then retry each server that
        // returned Busy in the previous round. If the server is still Busy, this continues, while
        // the backoff increases exponentially (by a factor of 2), until it hits 300ms, in which case we
        // give up. The request might still be retried by the caller (likely the DnsRetryHandle).
        //
        // Enforce an end-to-end deadline so the total time spent in this loop never exceeds the
        // configured timeout.  Without this, the pool can spend up to N × timeout (where N is the
        // number of servers) before returning an error — well past the point where clients have
        // given up and retransmitted the query.
        let deadline = Instant::now() + self.cx.options.timeout;

        let mut servers = VecDeque::from(servers);
        let mut backoff = Duration::from_millis(20);
        let mut busy = SmallVec::<[Arc<NameServer<P>>; 2]>::new();
        let mut err = NetError::NoConnections;
        let mut policy = ConnectionPolicy::default();

        loop {
            // Check the deadline before starting a new round of server attempts.
            if Instant::now() >= deadline {
                return Err(NetError::Timeout);
            }

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
                    // Cap the backoff sleep so we don't sleep past the deadline.
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(NetError::Timeout);
                    }
                    <<P as ConnectionProvider>::RuntimeProvider as RuntimeProvider>::Timer::delay_for(
                        backoff.min(remaining),
                    ).await;
                    servers.extend(busy.drain(..).filter(|ns| policy.allows_server(ns)));
                    backoff *= 2;
                    continue;
                }
                return Err(err);
            }

            // Track all servers in the parallel batch so we can penalize any
            // that are still in-flight when a winner is found.
            let in_flight = par_servers.iter().cloned().collect::<SmallVec<[_; 2]>>();

            let batch_start = Instant::now();
            let mut requests = par_servers
                .into_iter()
                .map(|server| {
                    let mut request = request.clone();

                    // Set the retry interval to 1.2 times the current decayed SRTT
                    let retry_interval =
                        Duration::from_micros((server.decayed_srtt() * 1.2) as u64);
                    request.options_mut().retry_interval = retry_interval;
                    debug!(?retry_interval, ip = ?server.ip(), "setting retry_interval");

                    let future = server.clone().send(request, policy, &self.cx);
                    async { (server, future.await) }
                })
                .collect::<FuturesUnordered<_>>();

            // Servers that have already completed (successfully or with an
            // error) — used to avoid double-penalizing them.
            let mut completed = SmallVec::<[IpAddr; 2]>::new();

            while let Some((server, result)) = requests.next().await {
                completed.push(server.ip());
                let e = match result {
                    Ok(response) if response.truncation => {
                        debug!("truncated response received, retrying over TCP");
                        policy.disable_udp = true;
                        err = NetError::from("received truncated response");
                        servers.push_front(server);
                        continue;
                    }
                    Ok(response) => {
                        // Penalize servers still in-flight (see `record_cancelled`).
                        let winner_rtt = batch_start.elapsed();
                        for abandoned in &in_flight {
                            if !completed.contains(&abandoned.ip()) {
                                debug!(ip = ?abandoned.ip(), ?winner_rtt, "recording cancelled parallel server");
                                abandoned.record_cancelled(winner_rtt);
                            }
                        }
                        return Ok(response);
                    }
                    Err(e) => e,
                };

                match &e {
                    // We assume the response is spoofed, so ignore it and avoid UDP server for this
                    // request to try and avoid further spoofing.
                    NetError::QueryCaseMismatch => {
                        servers.push_front(server);
                        policy.disable_udp = true;
                        continue;
                    }
                    // If the server is busy, try it again later if necessary.
                    NetError::Busy => busy.push(server),
                    // If the connection failed or timed out, try another one.
                    NetError::Io(_) | NetError::NoConnections | NetError::Timeout => {}
                    // If we got an `NXDomain` response from a server whose negative responses we
                    // don't trust, we should try another server.
                    NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                        response_code: ResponseCode::NXDomain,
                        ..
                    })) if !server.trust_negative_responses() => {}
                    _ => return Err(e),
                }

                err = most_specific(err, e);
            }
        }
    }
}

/// Compare two errors to see if one contains a server response.
fn most_specific(previous: NetError, current: NetError) -> NetError {
    match (&previous, &current) {
        (
            NetError::Dns(DnsError::NoRecordsFound { .. }),
            NetError::Dns(DnsError::NoRecordsFound { .. }),
        ) => return previous,
        (NetError::Dns(DnsError::NoRecordsFound { .. }), _) => return previous,
        (_, NetError::Dns(DnsError::NoRecordsFound { .. })) => return current,
        _ => (),
    }

    match (&previous, &current) {
        (NetError::Io { .. }, NetError::Io { .. }) => return previous,
        (NetError::Io { .. }, _) => return current,
        (_, NetError::Io { .. }) => return previous,
        _ => (),
    }

    match (&previous, &current) {
        (NetError::Timeout, NetError::Timeout) => return previous,
        (NetError::Timeout, _) => return previous,
        (_, NetError::Timeout) => return current,
        _ => (),
    }

    previous
}

/// Sorts servers by their decayed SRTT for query-statistics-based ordering.
///
/// Uses `sort_by_cached_key` to evaluate each server's decayed SRTT exactly
/// once. This is critical because `decayed_srtt()` reads shared mutable state
/// that can change between calls due to concurrent query completions, which
/// would violate the total-order invariant required by `sort_by`.
pub(crate) fn sort_servers_by_query_statistics<P: ConnectionProvider>(
    servers: &mut [Arc<NameServer<P>>],
) {
    // Positive f64 bit patterns sort in the same order as their float values,
    // so to_bits() is a valid u64 ordering key for non-negative SRTT values.
    servers.sort_by_cached_key(|s| s.decayed_srtt().to_bits());
}

/// Context for a [`NameServerPool`]
#[non_exhaustive]
pub struct PoolContext {
    /// Resolver options
    pub options: ResolverOpts,
    /// TLS configuration
    #[cfg(feature = "__tls")]
    pub tls: rustls::ClientConfig,
    /// Opportunistic probe budget
    pub opportunistic_probe_budget: AtomicU8,
    /// Opportunistic encryption configuration
    pub opportunistic_encryption: OpportunisticEncryption,
    /// Opportunistic encryption name server transport state
    pub transport_state: AsyncMutex<NameServerTransportState>,
    /// Answer address filter
    pub answer_address_filter: AccessControlSet,
}

impl PoolContext {
    /// Creates a new PoolContext
    #[cfg_attr(not(feature = "__tls"), expect(unused_variables))]
    pub fn new(options: ResolverOpts, tls: TlsConfig) -> Self {
        Self {
            answer_address_filter: options.answer_address_filter(),
            options,
            #[cfg(feature = "__tls")]
            tls: tls.config,
            opportunistic_probe_budget: AtomicU8::default(),
            opportunistic_encryption: OpportunisticEncryption::default(),
            transport_state: AsyncMutex::new(NameServerTransportState::default()),
        }
    }

    /// Set the opportunistic probe budget
    pub fn with_probe_budget(self, budget: u8) -> Self {
        self.opportunistic_probe_budget
            .store(budget, AtomicOrdering::SeqCst);
        self
    }

    /// Add an answer address filter
    pub fn with_answer_filter(mut self, answer_filter: AccessControlSet) -> Self {
        self.answer_address_filter = answer_filter;
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
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(transparent)]
pub struct NameServerTransportState(HashMap<IpAddr, ProtocolTransportState>);

impl NameServerTransportState {
    /// Return the count of nameservers with protocol transport state.
    pub fn nameserver_count(&self) -> usize {
        self.0.len()
    }

    /// Update the transport state for the given IP and protocol to record a connection initiation.
    pub(crate) fn initiate_connection(&mut self, ip: IpAddr, protocol: Protocol) {
        let protocol_state = self.0.entry(ip).or_default();
        *protocol_state.get_mut(protocol) = TransportState::default();
    }

    /// Update the transport state for the given IP and protocol to record a connection completion.
    pub(crate) fn complete_connection(&mut self, ip: IpAddr, protocol: Protocol) {
        let protocol_state = self.0.entry(ip).or_default();
        *protocol_state.get_mut(protocol) = TransportState::Success {
            last_response: None,
        };
    }

    /// Update the successful transport state for the given IP and protocol to record a response received.
    pub(crate) fn response_received(&mut self, ip: IpAddr, protocol: Protocol) {
        let Some(protocol_state) = self.0.get_mut(&ip) else {
            return;
        };
        let TransportState::Success { last_response, .. } = protocol_state.get_mut(protocol) else {
            return;
        };
        *last_response = Some(SystemTime::now());
    }

    /// Update the transport state for the given IP and protocol to record a received error.
    pub(crate) fn error_received(&mut self, ip: IpAddr, protocol: Protocol, error: &NetError) {
        let protocol_state = self.0.entry(ip).or_default();
        *protocol_state.get_mut(protocol) = match &error {
            NetError::Timeout => TransportState::TimedOut {
                #[cfg(any(feature = "__tls", feature = "__quic"))]
                completed_at: SystemTime::now(),
            },
            _ => TransportState::Failed {
                #[cfg(any(feature = "__tls", feature = "__quic"))]
                completed_at: SystemTime::now(),
            },
        };
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

        let Some(protocol_state) = self.0.get(&ip) else {
            return false;
        };

        let TransportState::Success { last_response, .. } = protocol_state.get(protocol) else {
            return false;
        };

        let Some(last_response) = last_response else {
            return false;
        };

        last_response.elapsed().unwrap_or(Duration::MAX) <= config.persistence_period
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

        let Some(protocol_state) = self.0.get(&ip) else {
            return true;
        };

        match protocol_state.get(protocol) {
            TransportState::Initiated => false,
            TransportState::Success { .. } => true,
            TransportState::Failed { completed_at } | TransportState::TimedOut { completed_at } => {
                completed_at.elapsed().unwrap_or(Duration::MAX) > config.damping_period
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
    pub(crate) fn set_last_response(&mut self, ip: IpAddr, protocol: Protocol, when: SystemTime) {
        let Some(protocol_state) = self.0.get_mut(&ip) else {
            return;
        };

        let TransportState::Success { last_response, .. } = protocol_state.get_mut(protocol) else {
            return;
        };

        *last_response = Some(when);
    }

    /// For testing, set the completion time for failed connections to the ip/protocol.
    #[cfg(all(test, feature = "__tls"))]
    pub(crate) fn set_failure_time(&mut self, ip: IpAddr, protocol: Protocol, when: SystemTime) {
        let protocol_state = self.0.entry(ip).or_default();
        *protocol_state.get_mut(protocol) = TransportState::Failed { completed_at: when };
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct ProtocolTransportState {
    #[cfg(feature = "__tls")]
    tls: TransportState,
    #[cfg(feature = "__quic")]
    quic: TransportState,
}

impl ProtocolTransportState {
    #[cfg_attr(not(any(feature = "__tls", feature = "__quic")), allow(dead_code))]
    fn get_mut(&mut self, protocol: Protocol) -> &mut TransportState {
        match protocol {
            #[cfg(feature = "__tls")]
            Protocol::Tls => &mut self.tls,
            #[cfg(feature = "__quic")]
            Protocol::Quic => &mut self.quic,
            _ => unreachable!("unsupported opportunistic encryption protocol: {protocol:?}"),
        }
    }

    #[cfg_attr(not(any(feature = "__tls", feature = "__quic")), allow(dead_code))]
    fn get(&self, protocol: Protocol) -> &TransportState {
        match protocol {
            #[cfg(feature = "__tls")]
            Protocol::Tls => &self.tls,
            #[cfg(feature = "__quic")]
            Protocol::Quic => &self.quic,
            _ => unreachable!("unsupported opportunistic encryption protocol: {protocol:?}"),
        }
    }
}

/// State tracked per nameserver IP/protocol to inform opportunistic encryption.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
enum TransportState {
    /// Connection attempt has been initiated.
    #[default]
    Initiated,
    /// Connection completed successfully.
    Success {
        /// The last instant at which a response was read on the connection (if any).
        last_response: Option<SystemTime>,
    },
    /// Connection failed with an error.
    Failed {
        /// The instant the connection attempt was completed at.
        #[cfg(any(feature = "__tls", feature = "__quic"))]
        completed_at: SystemTime,
    },
    /// Connection timed out.
    TimedOut {
        /// The instant the connection attempt was completed at.
        #[cfg(any(feature = "__tls", feature = "__quic"))]
        completed_at: SystemTime,
    },
}

#[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
pub use opportunistic_encryption_persistence::OpportunisticEncryptionStatePersistTask;

#[cfg(all(feature = "toml", any(feature = "__tls", feature = "__quic")))]
mod opportunistic_encryption_persistence {
    #[cfg(unix)]
    use std::fs::File;
    use std::{
        fs::{self, OpenOptions},
        io::{self, Write},
        marker::PhantomData,
        path::{Path, PathBuf},
    };

    use tracing::trace;

    use super::*;
    use crate::config::OpportunisticEncryptionPersistence;
    use crate::net::runtime::Spawn;

    /// A background task for periodically saving opportunistic encryption state.
    pub struct OpportunisticEncryptionStatePersistTask<T> {
        cx: Arc<PoolContext>,
        path: PathBuf,
        save_interval: Duration,
        _time: PhantomData<T>,
    }

    impl<T: Time> OpportunisticEncryptionStatePersistTask<T> {
        /// Starts the persistence task based on the given configuration.
        pub async fn start<P: RuntimeProvider>(
            config: OpportunisticEncryptionPersistence,
            pool_context: &Arc<PoolContext>,
            conn_provider: P,
        ) -> Result<Option<P::Handle>, String> {
            info!(
                path = %config.path.display(),
                save_interval = ?config.save_interval,
                "spawning encrypted transport state persistence task"
            );

            let new =
                OpportunisticEncryptionStatePersistTask::<P::Timer>::new(config, pool_context);

            // Try to save the state back immediately so we can surface write errors early
            // instead of when the background task runs later on.
            new.save(&*new.cx.transport_state.lock().await)
                .map_err(|err| {
                    format!(
                        "failed to save opportunistic encryption state: {path}: {err}",
                        path = new.path.display()
                    )
                })?;

            let mut handle = conn_provider.create_handle();
            handle.spawn_bg(new.run());
            Ok(Some(handle))
        }

        fn new(config: OpportunisticEncryptionPersistence, cx: &Arc<PoolContext>) -> Self {
            Self {
                cx: cx.clone(),
                path: config.path,
                save_interval: config.save_interval,
                _time: PhantomData,
            }
        }

        async fn run(self) {
            let Self {
                save_interval,
                path,
                cx,
                ..
            } = &self;

            loop {
                T::delay_for(*save_interval).await;
                trace!(path = %path.display(), ?save_interval, "persisting opportunistic encryption state");
                if let Err(e) = self.save(&*cx.transport_state.lock().await) {
                    error!("failed to save opportunistic encryption state: {e}");
                }
            }
        }

        fn save(&self, state: &NameServerTransportState) -> Result<(), io::Error> {
            let toml_content = toml::to_string_pretty(state).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to serialize state to TOML: {e}"),
                )
            })?;

            if let Some(parent) = parent_directory(&self.path) {
                fs::create_dir_all(parent)?;
            }

            let temp_path = {
                let mut temp = self.path.as_os_str().to_os_string();
                temp.push(".tmp");
                PathBuf::from(temp)
            };

            {
                let mut temp_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&temp_path)?;

                temp_file.write_all(toml_content.as_bytes())?;
                temp_file.sync_all()?;
            }

            #[cfg(unix)]
            if let Some(parent) = parent_directory(&self.path) {
                File::open(parent)?.sync_all()?;
            }

            fs::rename(&temp_path, &self.path)?;
            debug!(state_file = %self.path.display(), "saved opportunistic encryption state");
            Ok(())
        }
    }

    /// Gets the parent directory of an absolute or relative path.
    fn parent_directory(path: &Path) -> Option<&Path> {
        let parent = path.parent()?;
        // Special case: if the path has only one component, `parent()` will return an empty string. We
        // should return "." instead, a relative path pointing at the current directory.
        Some(match parent == Path::new("") {
            true => Path::new("."),
            false => parent,
        })
    }
}

/// RAII guard that removes a deduplication key from `active_requests` when dropped.
///
/// This is created only by the "creator" task (the one that inserted the key).
/// Using `Drop` guarantees the entry is removed even if the inner future panics,
/// preventing a poisoned [`SharedLookup`] from remaining in the map and causing
/// every subsequent request for the same key to also panic.
struct ActiveRequestCleanup {
    active_requests: Arc<Mutex<HashMap<Arc<CacheKey>, SharedLookup>>>,
    key: Arc<CacheKey>,
}

impl Drop for ActiveRequestCleanup {
    fn drop(&mut self) {
        self.active_requests.lock().remove(&self.key);
    }
}

/// Fields of a [`DnsRequest`] that are used as a key when memoizing queries.
#[derive(PartialEq, Eq, Hash)]
struct CacheKey {
    op_code: OpCode,
    recursion_desired: bool,
    checking_disabled: bool,
    queries: Vec<Query>,
    dnssec_ok: bool,
    client_subnet: Option<ClientSubnet>,
}

impl CacheKey {
    fn from_request(request: &DnsRequest) -> Self {
        let dnssec_ok;
        let client_subnet;
        if let Some(edns) = &request.edns {
            dnssec_ok = edns.flags().dnssec_ok;
            if let Some(EdnsOption::Subnet(subnet)) = edns.option(EdnsCode::Subnet) {
                client_subnet = Some(*subnet);
            } else {
                client_subnet = None;
            }
        } else {
            dnssec_ok = false;
            client_subnet = None;
        }
        Self {
            op_code: request.op_code,
            recursion_desired: request.recursion_desired,
            checking_disabled: request.checking_disabled,
            queries: request.queries.clone(),
            dnssec_ok,
            client_subnet,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedLookup(Shared<BoxFuture<'static, Option<Result<DnsResponse, NetError>>>>);

impl Future for SharedLookup {
    type Output = Result<DnsResponse, NetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx).map(|o| match o {
            Some(r) => r,
            None => Err("no response from nameserver".into()),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::collections::HashSet;
    use std::future::Future;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use futures_util::future;
    use test_support::{
        MockNetworkHandler, MockProvider, MockRecord, MockTcpStream, MockUdpSocket, subscribe,
    };
    use tokio::runtime::Runtime;

    use super::*;
    use crate::config::{NameServerConfig, ResolverConfig, ServerOrderingStrategy};
    use crate::net::runtime::{RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime};
    use crate::net::xfer::{DnsHandle, FirstAnswer};
    use crate::proto::op::{DnsRequestOptions, Query};
    use crate::proto::rr::{Name, RecordType};

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
        let name_server = Arc::new(NameServer::new([], tcp, &opts, conn_provider));
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

        assert!(!response.answers.is_empty());

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

        assert!(!response.answers.is_empty());

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );
    }

    /// Regression test: when the first name server in the pool times out, the pool should
    /// try the remaining servers rather than returning the timeout error immediately.
    ///
    /// Before the fix (adding `NetError::Timeout` to the retry match arm in `try_send`),
    /// a timeout from one server would cause the entire lookup to fail even when other
    /// servers in the pool could have answered successfully.
    #[tokio::test]
    async fn test_pool_retries_on_timeout() {
        subscribe();

        let timeout_ip = IpAddr::from([10, 0, 0, 1]);
        let good_ip = IpAddr::from([10, 0, 0, 2]);
        let query_name = Name::from_str("example.com.").unwrap();

        // Set up a mock handler where the good server returns a valid A record.
        let responses = vec![MockRecord::a(good_ip, &query_name, good_ip)];
        let handler = MockNetworkHandler::new(responses);
        let mock_provider = MockProvider::new(handler);

        // Wrap in TimeoutProvider so that the timeout_ip always fails with TimedOut.
        let provider = TimeoutProvider::new(mock_provider, vec![timeout_ip]);

        let opts = ResolverOpts {
            num_concurrent_reqs: 1,
            server_ordering_strategy: ServerOrderingStrategy::UserProvidedOrder,
            ..ResolverOpts::default()
        };

        let pool = NameServerPool::from_nameservers(
            vec![
                Arc::new(NameServer::new(
                    [].into_iter(),
                    NameServerConfig::udp(timeout_ip),
                    &opts,
                    provider.clone(),
                )),
                Arc::new(NameServer::new(
                    [].into_iter(),
                    NameServerConfig::udp(good_ip),
                    &opts,
                    provider.clone(),
                )),
            ],
            Arc::new(PoolContext::new(opts, TlsConfig::new().unwrap())),
        );

        // This should succeed: the pool should fall through the timeout from the first
        // server and get the answer from the second server.
        let response = pool
            .lookup(
                Query::query(query_name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("pool should retry on timeout and succeed with the second server");

        assert!(
            !response.answers.is_empty(),
            "expected A record in response"
        );
    }

    /// Regression test: when a server times out, its server-level SRTT should be penalized
    /// so that it gets deprioritized in future pool ordering.
    #[tokio::test]
    async fn test_timeout_penalizes_server_srtt() {
        subscribe();

        let timeout_ip = IpAddr::from([10, 0, 0, 1]);
        let good_ip = IpAddr::from([10, 0, 0, 2]);
        let query_name = Name::from_str("example.com.").unwrap();

        let responses = vec![MockRecord::a(good_ip, &query_name, good_ip)];
        let handler = MockNetworkHandler::new(responses);
        let mock_provider = MockProvider::new(handler);
        let provider = TimeoutProvider::new(mock_provider, vec![timeout_ip]);

        let opts = ResolverOpts {
            num_concurrent_reqs: 1,
            server_ordering_strategy: ServerOrderingStrategy::UserProvidedOrder,
            ..ResolverOpts::default()
        };

        let ns_timeout = Arc::new(NameServer::new(
            [].into_iter(),
            NameServerConfig::udp(timeout_ip),
            &opts,
            provider.clone(),
        ));
        let ns_good = Arc::new(NameServer::new(
            [].into_iter(),
            NameServerConfig::udp(good_ip),
            &opts,
            provider.clone(),
        ));

        let initial_srtt_timeout = ns_timeout.decayed_srtt();

        let pool = NameServerPool::from_nameservers(
            vec![ns_timeout.clone(), ns_good.clone()],
            Arc::new(PoolContext::new(opts, TlsConfig::new().unwrap())),
        );

        // Perform a lookup - the first server will timeout, second will succeed.
        let _response = pool
            .lookup(
                Query::query(query_name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("lookup should succeed via second server");

        // The timeout server's SRTT should have been penalized (increased).
        assert!(
            ns_timeout.decayed_srtt() > initial_srtt_timeout,
            "timeout server SRTT should increase after failure: {} should be > {}",
            ns_timeout.decayed_srtt(),
            initial_srtt_timeout,
        );

        // The good server's SRTT should not have been penalized.
        // It may have changed slightly due to recording a successful RTT, but should
        // not have jumped to the failure penalty value.
        let failure_penalty = 5_000_000.0_f64; // SRTT failure penalty
        assert!(
            ns_good.decayed_srtt() < failure_penalty,
            "good server SRTT should not be penalized: {}",
            ns_good.decayed_srtt(),
        );
    }

    /// A [`RuntimeProvider`] wrapper that returns `io::ErrorKind::TimedOut` from `bind_udp`
    /// for a specified set of server IPs, simulating a connection-level timeout. All other
    /// IPs are delegated to the inner provider.
    #[derive(Clone)]
    struct TimeoutProvider {
        inner: MockProvider,
        timeout_ips: Arc<HashSet<IpAddr>>,
    }

    impl TimeoutProvider {
        fn new(inner: MockProvider, timeout_ips: Vec<IpAddr>) -> Self {
            Self {
                inner,
                timeout_ips: Arc::new(timeout_ips.into_iter().collect()),
            }
        }
    }

    impl RuntimeProvider for TimeoutProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = MockUdpSocket;
        type Tcp = MockTcpStream;

        fn create_handle(&self) -> Self::Handle {
            self.inner.create_handle()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            timeout: Option<Duration>,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Tcp, io::Error>> + Send>> {
            if self.timeout_ips.contains(&server_addr.ip()) {
                Box::pin(future::ready(Err(io::Error::from(io::ErrorKind::TimedOut))))
            } else {
                self.inner.connect_tcp(server_addr, bind_addr, timeout)
            }
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            server_addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Udp, io::Error>> + Send>> {
            if self.timeout_ips.contains(&server_addr.ip()) {
                Box::pin(future::ready(Err(io::Error::from(io::ErrorKind::TimedOut))))
            } else {
                self.inner.bind_udp(local_addr, server_addr)
            }
        }
    }

    /// Regression test: an unreachable server racing in parallel must be penalized.
    ///
    /// When `num_concurrent_reqs >= 2`, multiple servers are queried in parallel
    /// via `FuturesUnordered`. If a reachable server responds first, the
    /// unreachable server's future is dropped (cancelled). Before the fix, this
    /// meant `record_failure()` was never called for the unreachable server,
    /// leaving its SRTT unchanged so it would be retried on every subsequent
    /// query.
    #[tokio::test]
    async fn test_cancelled_parallel_server_is_penalized() {
        subscribe();

        let unreachable_ip = IpAddr::from([10, 0, 0, 1]);
        let good_ip = IpAddr::from([10, 0, 0, 2]);
        let query_name = Name::from_str("example.com.").unwrap();

        let responses = vec![MockRecord::a(good_ip, &query_name, good_ip)];
        let handler = MockNetworkHandler::new(responses);
        let mock_provider = MockProvider::new(handler);
        let provider = PendingProvider::new(mock_provider, vec![unreachable_ip]);

        let opts = ResolverOpts {
            // Both servers are queried in parallel — the key condition for this bug.
            num_concurrent_reqs: 2,
            server_ordering_strategy: ServerOrderingStrategy::UserProvidedOrder,
            ..ResolverOpts::default()
        };

        let ns_unreachable = Arc::new(NameServer::new(
            [].into_iter(),
            NameServerConfig::udp(unreachable_ip),
            &opts,
            provider.clone(),
        ));
        let ns_good = Arc::new(NameServer::new(
            [].into_iter(),
            NameServerConfig::udp(good_ip),
            &opts,
            provider.clone(),
        ));

        let initial_srtt = ns_unreachable.decayed_srtt();

        let pool = NameServerPool::from_nameservers(
            vec![ns_unreachable.clone(), ns_good.clone()],
            Arc::new(PoolContext::new(opts, TlsConfig::new().unwrap())),
        );

        // The good server wins the race; the unreachable server's future is cancelled.
        let _response = pool
            .lookup(
                Query::query(query_name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("lookup should succeed via good server");

        // The unreachable server's SRTT must have increased despite its future
        // being cancelled (not completing with an error).
        assert!(
            ns_unreachable.decayed_srtt() > initial_srtt,
            "unreachable server SRTT should increase after being cancelled: {} should be > {}",
            ns_unreachable.decayed_srtt(),
            initial_srtt,
        );

        // The good server should not have been penalized.
        let failure_penalty = 5_000_000.0_f64;
        assert!(
            ns_good.decayed_srtt() < failure_penalty,
            "good server SRTT should not be penalized: {}",
            ns_good.decayed_srtt(),
        );
    }

    /// A [`RuntimeProvider`] wrapper where specified IPs never complete their
    /// connection — the future stays pending forever. This simulates an
    /// unreachable server (SYN sent, no SYN-ACK) where the OS TCP handshake
    /// hasn't timed out yet.
    #[derive(Clone)]
    struct PendingProvider {
        inner: MockProvider,
        pending_ips: Arc<HashSet<IpAddr>>,
    }

    impl PendingProvider {
        fn new(inner: MockProvider, pending_ips: Vec<IpAddr>) -> Self {
            Self {
                inner,
                pending_ips: Arc::new(pending_ips.into_iter().collect()),
            }
        }
    }

    impl RuntimeProvider for PendingProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = MockUdpSocket;
        type Tcp = MockTcpStream;

        fn create_handle(&self) -> Self::Handle {
            self.inner.create_handle()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            timeout: Option<Duration>,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Tcp, io::Error>> + Send>> {
            if self.pending_ips.contains(&server_addr.ip()) {
                Box::pin(future::pending())
            } else {
                self.inner.connect_tcp(server_addr, bind_addr, timeout)
            }
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            server_addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Udp, io::Error>> + Send>> {
            if self.pending_ips.contains(&server_addr.ip()) {
                Box::pin(future::pending())
            } else {
                self.inner.bind_udp(local_addr, server_addr)
            }
        }
    }

    /// Regression test: `sort_servers_by_query_statistics` must not panic when
    /// SRTT values are concurrently modified.
    ///
    /// `record()` and `record_failure()` can modify a server's SRTT while
    /// another thread sorts the server list. With `sort_by`, the comparator
    /// re-evaluates `decayed_srtt()` on every comparison, observing values
    /// that change between calls and violating the total-order invariant.
    /// The fix uses `sort_by_cached_key`, which evaluates each key exactly
    /// once before sorting.
    #[test]
    fn test_sort_by_decayed_srtt_does_not_panic() {
        let opts = ResolverOpts::default();
        let mock_provider = MockProvider::new(MockNetworkHandler::new(vec![]));

        let mut servers = (1..=50)
            .map(|i| {
                let ns = Arc::new(NameServer::new(
                    [],
                    NameServerConfig::udp(IpAddr::from([10, 0, 0, i])),
                    &opts,
                    mock_provider.clone(),
                ));
                // Activate the time-based decay path by recording a failure,
                // which sets `last_update` to `Some(now)`.
                ns.test_record_failure();
                ns
            })
            .collect::<Vec<_>>();

        // Spawn a thread that continuously modifies SRTT values, simulating
        // concurrent queries completing on other threads.
        let servers_writer = servers.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_writer = stop.clone();
        let writer = thread::spawn(move || {
            while !stop_writer.load(Ordering::Relaxed) {
                for s in &servers_writer {
                    s.test_record_failure();
                }
            }
        });

        // Ensure the writer thread stops even if the test panics.
        struct StopGuard(Arc<AtomicBool>);
        impl Drop for StopGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let _guard = StopGuard(stop.clone());

        // Call the production sort function many times while the writer
        // thread concurrently modifies SRTT values. With sort_by_cached_key
        // this is safe. With sort_by, the concurrent modifications cause
        // inconsistent comparisons that panic the sort.
        for _ in 0..100_000 {
            sort_servers_by_query_statistics(&mut servers);
        }

        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
    }
}
