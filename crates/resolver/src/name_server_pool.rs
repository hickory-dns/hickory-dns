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
use std::time::{Duration, SystemTime};

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
    op::{DnsRequest, DnsRequestOptions, DnsResponse, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{
            A, AAAA,
            opt::{ClientSubnet, EdnsCode, EdnsOption},
        },
    },
    runtime::{RuntimeProvider, Time},
    xfer::{DnsHandle, Protocol},
};

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider> {
    state: Arc<PoolState<P>>,
    active_requests: Arc<Mutex<HashMap<Arc<CacheKey>, SharedLookup>>>,
    ttl: Option<TtlInstant>,
    zone: Option<Name>,
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
        if let Some(edns) = request.extensions() {
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
            op_code: request.op_code(),
            recursion_desired: request.recursion_desired(),
            checking_disabled: request.checking_disabled(),
            queries: request.queries().to_vec(),
            dnssec_ok,
            client_subnet,
        }
    }
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
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;
    type Runtime = P::RuntimeProvider;

    fn lookup(&self, query: Query, mut options: DnsRequestOptions) -> Self::Response {
        debug!("querying: {} {:?}", query.name(), query.query_type());
        options.case_randomization = self.state.cx.options.case_randomization;
        self.send(DnsRequest::from_query(query, options))
    }

    fn send(&self, request: DnsRequest) -> Self::Response {
        let state = self.state.clone();
        let acs = self.state.cx.answer_address_filter.clone();
        let active_requests = self.active_requests.clone();

        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries());
            let query = match request.queries().first() {
                Some(q) => q.clone(),
                None => return Err("no query in request".into()),
            };

            let key = Arc::new(CacheKey::from_request(&request));

            let lookup = {
                let mut active = active_requests.lock();
                if let Some(existing) = active.get(&key) {
                    debug!(%query, "query currently in progress - returning shared lookup");
                    existing.clone()
                } else {
                    info!(%query, "creating new shared lookup");

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
                    ).await;
                    servers.extend(busy.drain(..).filter(|ns| policy.allows_server(ns)));
                    backoff *= 2;
                    continue;
                }
                return Err(err);
            }

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
    #[cfg(feature = "__tls")]
    pub tls: rustls::ClientConfig,
    /// Opportunistic probe budget
    pub opportunistic_probe_budget: AtomicU8,
    /// Opportunistic encryption configuration
    pub opportunistic_encryption: OpportunisticEncryption,
    /// Opportunistic encryption name server transport state
    pub transport_state: AsyncMutex<NameServerTransportState>,
    /// Answer address filter
    pub answer_address_filter: Option<AccessControlSet>,
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
    pub(crate) fn error_received(&mut self, ip: IpAddr, protocol: Protocol, error: &ProtoError) {
        let protocol_state = self.0.entry(ip).or_default();
        *protocol_state.get_mut(protocol) = match error.kind() {
            ProtoErrorKind::Timeout => TransportState::TimedOut {
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
    use crate::proto::runtime::Spawn;

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
            config: &OpportunisticEncryptionConfig,
            pool_context: &Arc<PoolContext>,
            conn_provider: P,
        ) -> Result<Option<P::Handle>, String> {
            let Some(persistence) = &config.persistence else {
                return Ok(None);
            };

            info!(
                path = %persistence.path.display(),
                save_interval = ?persistence.save_interval,
                "spawning encrypted transport state persistence task"
            );

            let new =
                OpportunisticEncryptionStatePersistTask::<P::Timer>::new(persistence, pool_context);

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

        fn new(
            config: &OpportunisticEncryptionPersistence,
            pool_context: &Arc<PoolContext>,
        ) -> Self {
            Self {
                cx: pool_context.clone(),
                path: config.path.clone(),
                save_interval: config.save_interval,
                _time: PhantomData,
            }
        }

        async fn run(self) -> Result<(), ProtoError> {
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

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::{net::IpAddr, str::FromStr};

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
