// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp;
use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
#[cfg(not(test))]
use std::time::{Duration, Instant};

use futures_util::lock::Mutex as AsyncMutex;
#[cfg(feature = "metrics")]
use metrics::{Counter, Gauge, Unit, counter, describe_counter, describe_gauge, gauge};
use parking_lot::Mutex as SyncMutex;
#[cfg(test)]
use tokio::time::{Duration, Instant};
use tracing::{debug, error, warn};

use crate::config::{
    ConnectionConfig, NameServerConfig, OpportunisticEncryption, ResolverOpts,
    ServerOrderingStrategy,
};
use crate::connection_provider::ConnectionProvider;
use crate::name_server_pool::{NameServerTransportState, PoolContext};
use crate::proto::{
    DnsError, NoRecords, ProtoError, ProtoErrorKind,
    op::{DnsRequest, DnsRequestOptions, DnsResponse, Query, ResponseCode},
    rr::{Name, RecordType},
    runtime::{RuntimeProvider, Spawn},
    xfer::{DnsHandle, FirstAnswer, Protocol},
};

/// A remote DNS server, identified by its IP address.
///
/// This potentially holds multiple open connections to the server, according to the
/// configured protocols, and will make new connections as needed.
pub struct NameServer<P: ConnectionProvider> {
    config: NameServerConfig,
    connections: AsyncMutex<Vec<ConnectionState<P>>>,
    /// Budget for opportunistic encryption probes.
    opportunistic_probe_budget: Arc<AtomicU8>,
    /// Metrics related to opportunistic encryption probes.
    #[cfg(feature = "metrics")]
    opportunistic_probe_metrics: ProbeMetrics,
    server_srtt: DecayingSrtt,
    connection_provider: P,
}

impl<P: ConnectionProvider> NameServer<P> {
    /// Create a new [`NameServer`] with the given connections and configuration.
    ///
    /// The `connections` will usually be empty.
    pub fn new(
        connections: impl IntoIterator<Item = (Protocol, P::Conn)>,
        config: NameServerConfig,
        options: &ResolverOpts,
        opportunistic_probe_budget: Arc<AtomicU8>,
        connection_provider: P,
    ) -> Self {
        let mut connections = connections
            .into_iter()
            .map(|(protocol, handle)| ConnectionState::new(handle, protocol))
            .collect::<Vec<_>>();

        // Unless the user specified that we should follow the configured order,
        // re-order the connections to prioritize UDP.
        if options.server_ordering_strategy != ServerOrderingStrategy::UserProvidedOrder {
            connections.sort_by_key(|ns| ns.protocol != Protocol::Udp);
        }

        Self {
            config,
            connections: AsyncMutex::new(connections),
            server_srtt: DecayingSrtt::new(Duration::from_micros(rand::random_range(1..32))),
            opportunistic_probe_budget,
            #[cfg(feature = "metrics")]
            opportunistic_probe_metrics: ProbeMetrics::default(),
            connection_provider,
        }
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    pub(crate) async fn send(
        self: Arc<Self>,
        request: DnsRequest,
        policy: ConnectionPolicy,
        cx: &Arc<PoolContext>,
    ) -> Result<DnsResponse, ProtoError> {
        let (handle, meta, protocol) = self.connected_mut_client(policy, cx).await?;
        let now = Instant::now();
        let response = handle.send(request).first_answer().await;
        let rtt = now.elapsed();

        match response {
            Ok(response) => {
                meta.set_status(Status::Established);
                let result = DnsError::from_response(response);
                let error = match result {
                    Ok(response) => {
                        meta.srtt.record(rtt);
                        self.server_srtt.record(rtt);
                        if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
                            cx.transport_state()
                                .await
                                .response_received(self.config.ip, protocol);
                        }
                        return Ok(response);
                    }
                    Err(error) => error,
                };

                let update = match error {
                    DnsError::NoRecordsFound(NoRecords {
                        response_code: ResponseCode::ServFail,
                        ..
                    }) => Some(true),
                    DnsError::NoRecordsFound(NoRecords { .. }) => Some(false),
                    _ => None,
                };

                match update {
                    Some(true) => {
                        meta.srtt.record(rtt);
                        self.server_srtt.record(rtt);
                    }
                    Some(false) => {
                        // record the failure
                        meta.srtt.record_failure();
                        self.server_srtt.record_failure();
                    }
                    None => {}
                }

                let err = ProtoError::from(error);
                if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
                    cx.transport_state()
                        .await
                        .error_received(self.config.ip, protocol, &err)
                }
                Err(err)
            }
            Err(error) => {
                debug!(config = ?self.config, %error, "failed to connect to name server");

                // this transitions the state to failure
                meta.set_status(Status::Failed);

                // record the failure
                match error.kind() {
                    ProtoErrorKind::Busy | ProtoErrorKind::Io(_) | ProtoErrorKind::Timeout => {
                        meta.srtt.record_failure()
                    }
                    #[cfg(feature = "__quic")]
                    ProtoErrorKind::QuinnConfigError(_)
                    | ProtoErrorKind::QuinnConnect(_)
                    | ProtoErrorKind::QuinnConnection(_)
                    | ProtoErrorKind::QuinnTlsConfigError(_) => meta.srtt.record_failure(),
                    #[cfg(feature = "__tls")]
                    ProtoErrorKind::RustlsError(_) => meta.srtt.record_failure(),
                    _ => {}
                }

                if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
                    cx.transport_state()
                        .await
                        .error_received(self.config.ip, protocol, &error);
                }

                // These are connection failures, not lookup failures, that is handled in the resolver layer
                Err(error)
            }
        }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection
    async fn connected_mut_client(
        &self,
        policy: ConnectionPolicy,
        cx: &Arc<PoolContext>,
    ) -> Result<(P::Conn, Arc<ConnectionMeta>, Protocol), ProtoError> {
        let mut connections = self.connections.lock().await;
        connections.retain(|conn| matches!(conn.meta.status(), Status::Init | Status::Established));
        if let Some(conn) = policy.select_connection(
            self.config.ip,
            &*cx.transport_state().await,
            &cx.opportunistic_encryption,
            &connections,
        ) {
            return Ok((conn.handle.clone(), conn.meta.clone(), conn.protocol));
        }

        debug!(config = ?self.config, "connecting");
        let config = policy
            .select_connection_config(
                self.config.ip,
                &*cx.transport_state().await,
                &cx.opportunistic_encryption,
                &self.config.connections,
            )
            .ok_or_else(|| ProtoError::from(ProtoErrorKind::NoConnections))?;

        let protocol = config.protocol.to_protocol();
        if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
            cx.transport_state()
                .await
                .initiate_connection(self.config.ip, protocol);
        } else if cx.opportunistic_encryption.is_enabled() && !protocol.is_encrypted() {
            self.consider_probe_encrypted_transport(
                &policy,
                cx,
                self.opportunistic_probe_budget.clone(),
            )
            .await;
        }

        let handle = Box::pin(self.connection_provider.new_connection(
            self.config.ip,
            config,
            cx,
        )?)
        .await?;

        if cx.opportunistic_encryption.is_enabled() && protocol.is_encrypted() {
            cx.transport_state()
                .await
                .complete_connection(self.config.ip, protocol);
        }

        // establish a new connection
        let state = ConnectionState::new(handle.clone(), protocol);
        let meta = state.meta.clone();
        connections.push(state);
        Ok((handle, meta, protocol))
    }

    pub(super) fn protocols(&self) -> impl Iterator<Item = Protocol> + '_ {
        self.config
            .connections
            .iter()
            .map(|conn| conn.protocol.to_protocol())
    }

    pub(crate) fn decayed_srtt(&self) -> f64 {
        self.server_srtt.current()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn is_connected(&self) -> bool {
        let Some(connections) = self.connections.try_lock() else {
            // assuming that if someone has it locked it will be or is connected
            return true;
        };

        connections.iter().any(|conn| match conn.meta.status() {
            Status::Established | Status::Init => true,
            Status::Failed => false,
        })
    }

    pub(crate) fn trust_negative_responses(&self) -> bool {
        self.config.trust_negative_responses
    }

    async fn consider_probe_encrypted_transport(
        &self,
        policy: &ConnectionPolicy,
        cx: &Arc<PoolContext>,
        opportunistic_probe_budget: Arc<AtomicU8>,
    ) {
        let Some(probe_config) =
            policy.select_encrypted_connection_config(&self.config.connections)
        else {
            warn!("no encrypted connection configs available for probing");
            return;
        };

        let probe_protocol = probe_config.protocol.to_protocol();
        let should_probe = {
            let state = cx.transport_state().await;
            state.should_probe_encrypted(
                self.config.ip,
                probe_protocol,
                &cx.opportunistic_encryption,
            )
        };

        if !should_probe {
            return;
        }

        if let Err(err) =
            self.probe_encrypted_transport(cx, probe_config, opportunistic_probe_budget)
        {
            error!(%err, "opportunistic encrypted probe attempt failed");
        }
    }

    fn probe_encrypted_transport(
        &self,
        cx: &Arc<PoolContext>,
        probe_config: &ConnectionConfig,
        opportunistic_probe_budget: Arc<AtomicU8>,
    ) -> Result<(), ProtoError> {
        let budget = opportunistic_probe_budget.load(Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        self.opportunistic_probe_metrics.probe_budget.set(budget);
        if budget == 0
            || opportunistic_probe_budget
                .compare_exchange_weak(budget, budget - 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            debug!("no remaining budget for opportunistic probing");
            return Ok(());
        }

        let connect = ProbeRequest::new(
            probe_config,
            self,
            cx,
            #[cfg(feature = "metrics")]
            self.opportunistic_probe_metrics.clone(),
        )?;
        self.connection_provider
            .runtime_provider()
            .create_handle()
            .spawn_bg(connect.run());

        Ok(())
    }
}

struct ProbeRequest<P: ConnectionProvider> {
    ip: IpAddr,
    proto: Protocol,
    connecting: P::FutureConn,
    budget: Arc<AtomicU8>,
    context: Arc<PoolContext>,
    #[cfg(feature = "metrics")]
    metrics: ProbeMetrics,
    provider: PhantomData<P>,
}

impl<P: ConnectionProvider> ProbeRequest<P> {
    fn new(
        config: &ConnectionConfig,
        ns: &NameServer<P>,
        cx: &Arc<PoolContext>,
        #[cfg(feature = "metrics")] metrics: ProbeMetrics,
    ) -> Result<Self, io::Error> {
        Ok(Self {
            ip: ns.config.ip,
            proto: config.protocol.to_protocol(),
            connecting: ns
                .connection_provider
                .new_connection(ns.config.ip, config, cx)?,
            budget: ns.opportunistic_probe_budget.clone(),
            context: cx.clone(),
            #[cfg(feature = "metrics")]
            metrics,
            provider: PhantomData,
        })
    }

    async fn run(self) -> Result<(), ProtoError> {
        let Self {
            ip,
            proto,
            connecting,
            budget,
            context,
            #[cfg(feature = "metrics")]
            metrics,
            provider: _,
        } = self;

        context
            .transport_state()
            .await
            .initiate_connection(ip, proto);
        #[cfg(feature = "metrics")]
        metrics.increment_attempts(proto);

        let conn = match connecting.await {
            Ok(conn) => conn,
            Err(err) => {
                debug!(?proto, "probe connection failed");
                #[cfg(feature = "metrics")]
                metrics.increment_errors(proto, &err);
                context
                    .transport_state()
                    .await
                    .error_received(ip, proto, &err);
                return Ok(());
            }
        };

        debug!(?proto, "probe connection succeeded");
        context
            .transport_state()
            .await
            .complete_connection(ip, proto);

        match conn
            .send(DnsRequest::from_query(
                Query::query(Name::root(), RecordType::NS),
                DnsRequestOptions::default(),
            ))
            .first_answer()
            .await
        {
            Ok(_) => {
                debug!(?proto, "probe query succeeded");
                #[cfg(feature = "metrics")]
                metrics.increment_successes(proto);
                context.transport_state().await.response_received(ip, proto);
            }
            Err(err) => {
                debug!(?proto, ?err, "probe query failed");
                #[cfg(feature = "metrics")]
                metrics.increment_errors(proto, &err);
                context
                    .transport_state()
                    .await
                    .error_received(ip, proto, &err);
            }
        }

        let _prev = budget.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        metrics.probe_budget.set(_prev + 1);
        Ok(())
    }
}

#[cfg(feature = "metrics")]
#[derive(Clone)]
struct ProbeMetrics {
    #[cfg(feature = "__tls")]
    tls_probe_metrics: ProbeProtocolMetrics,
    #[cfg(feature = "__quic")]
    quic_probe_metrics: ProbeProtocolMetrics,
    probe_budget: Gauge,
}

#[cfg(feature = "metrics")]
impl ProbeMetrics {
    fn increment_attempts(&self, proto: Protocol) {
        match proto {
            #[cfg(feature = "__tls")]
            Protocol::Tls => self.tls_probe_metrics.probe_attempts.increment(1),
            #[cfg(feature = "__quic")]
            Protocol::Quic => self.quic_probe_metrics.probe_attempts.increment(1),
            _ => {
                warn!("probe protocol {proto} not supported for metrics");
            }
        }
    }

    fn increment_errors(&self, proto: Protocol, err: &ProtoError) {
        match (&err.kind, proto) {
            #[cfg(feature = "__tls")]
            (ProtoErrorKind::Timeout, Protocol::Tls) => {
                self.tls_probe_metrics.probe_timeouts.increment(1)
            }
            #[cfg(feature = "__tls")]
            (_, Protocol::Tls) => self.tls_probe_metrics.probe_errors.increment(1),
            #[cfg(feature = "__quic")]
            (ProtoErrorKind::Timeout, Protocol::Quic) => {
                self.quic_probe_metrics.probe_timeouts.increment(1)
            }
            #[cfg(feature = "__quic")]
            (_, Protocol::Quic) => self.quic_probe_metrics.probe_errors.increment(1),
            _ => {
                warn!("probe protocol {proto} not supported for metrics");
            }
        }
    }

    fn increment_successes(&self, proto: Protocol) {
        match proto {
            #[cfg(feature = "__tls")]
            Protocol::Tls => self.tls_probe_metrics.probe_successes.increment(1),
            #[cfg(feature = "__quic")]
            Protocol::Quic => self.quic_probe_metrics.probe_successes.increment(1),
            _ => {
                warn!("probe protocol {proto} not supported for metrics");
            }
        }
    }
}

#[cfg(feature = "metrics")]
impl Default for ProbeMetrics {
    fn default() -> Self {
        describe_gauge!(
            "hickory_resolver_probe_budget_total",
            Unit::Count,
            "Count of remaining opportunistic encrypted name server probe requests allowed by budget."
        );
        let probe_budget = gauge!("hickory_resolver_probe_budget_total");

        Self {
            #[cfg(feature = "__tls")]
            tls_probe_metrics: ProbeProtocolMetrics::new(Protocol::Tls),
            #[cfg(feature = "__quic")]
            quic_probe_metrics: ProbeProtocolMetrics::new(Protocol::Quic),
            probe_budget,
        }
    }
}

#[cfg(feature = "metrics")]
#[derive(Clone)]
struct ProbeProtocolMetrics {
    probe_attempts: Counter,
    probe_errors: Counter,
    probe_timeouts: Counter,
    probe_successes: Counter,
}

#[cfg(feature = "metrics")]
impl ProbeProtocolMetrics {
    fn new(protocol: Protocol) -> Self {
        describe_counter!(
            "hickory_resolver_probe_attempts_total",
            Unit::Count,
            "Number of opportunistic encrypted name server probe requests attempted."
        );
        let probe_attempts =
            counter!("hickory_resolver_probe_attempts_total", "protocol" => protocol.to_string());

        describe_counter!(
            "hickory_resolver_probe_errors_total",
            Unit::Count,
            "Number of opportunistic encrypted name server probe requests that failed due to an error."
        );
        let probe_errors =
            counter!("hickory_resolver_probe_errors_total", "protocol" => protocol.to_string());

        describe_counter!(
            "hickory_resolver_probe_timeouts_total",
            Unit::Count,
            "Number of opportunistic encrypted name server probe requests that failed due to a timeout."
        );
        let probe_timeouts =
            counter!("hickory_resolver_probe_timeouts_total", "protocol" => protocol.to_string());

        describe_counter!(
            "hickory_resolver_probe_successes_total",
            Unit::Count,
            "Number of opportunistic encrypted name server probe requests that succeeded"
        );
        let probe_successes =
            counter!("hickory_resolver_probe_successes_total", "protocol" => protocol.to_string());

        Self {
            probe_attempts,
            probe_errors,
            probe_timeouts,
            probe_successes,
        }
    }
}

struct ConnectionState<P: ConnectionProvider> {
    protocol: Protocol,
    handle: P::Conn,
    meta: Arc<ConnectionMeta>,
}

impl<P: ConnectionProvider> ConnectionState<P> {
    fn new(handle: P::Conn, protocol: Protocol) -> Self {
        Self {
            protocol,
            handle,
            meta: Arc::new(ConnectionMeta::default()),
        }
    }
}

struct ConnectionMeta {
    status: AtomicU8,
    srtt: DecayingSrtt,
}

impl ConnectionMeta {
    fn set_status(&self, status: Status) {
        self.status.store(status.into(), Ordering::Release);
    }

    fn status(&self) -> Status {
        Status::from(self.status.load(Ordering::Acquire))
    }
}

impl Default for ConnectionMeta {
    fn default() -> Self {
        // Initialize the SRTT to a randomly generated value that represents a
        // very low RTT. Such a value helps ensure that each server is attempted
        // early.
        Self {
            status: AtomicU8::new(Status::Init.into()),
            srtt: DecayingSrtt::new(Duration::from_micros(rand::random_range(1..32))),
        }
    }
}

struct DecayingSrtt {
    /// The smoothed round-trip time (SRTT).
    ///
    /// This value represents an exponentially weighted moving average (EWMA) of
    /// recorded latencies. The algorithm for computing this value is based on
    /// the following:
    ///
    /// <https://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance>
    ///
    /// It is also partially inspired by the BIND and PowerDNS implementations:
    ///
    /// - <https://github.com/isc-projects/bind9/blob/7bf8a7ab1b280c1021bf1e762a239b07aac3c591/lib/dns/adb.c#L3487>
    /// - <https://github.com/PowerDNS/pdns/blob/7c5f9ae6ae4fb17302d933eaeebc8d6f0249aab2/pdns/syncres.cc#L123>
    ///
    /// The algorithm for computing and using this value can be summarized as
    /// follows:
    ///
    /// 1. The value is initialized to a random value that represents a very low
    ///    latency.
    /// 2. If the round-trip time (RTT) was successfully measured for a query,
    ///    then it is incorporated into the EWMA using the formula linked above.
    /// 3. If the RTT could not be measured (i.e. due to a connection failure),
    ///    then a constant penalty factor is applied to the EWMA.
    /// 4. When comparing EWMA values, a time-based decay is applied to each
    ///    value. Note that this decay is only applied at read time.
    ///
    /// For the original discussion regarding this algorithm, see
    /// <https://github.com/hickory-dns/hickory-dns/issues/1702>.
    srtt_microseconds: AtomicU32,

    /// The last time the `srtt_microseconds` value was updated.
    last_update: SyncMutex<Option<Instant>>,
}

impl DecayingSrtt {
    fn new(initial_srtt: Duration) -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(initial_srtt.as_micros() as u32),
            last_update: SyncMutex::new(None),
        }
    }

    fn record(&self, rtt: Duration) {
        // If the cast on the result does overflow (it shouldn't), then the
        // value is saturated to u32::MAX, which is above the `MAX_SRTT_MICROS`
        // limit (meaning that any potential overflow is inconsequential).
        // See https://github.com/rust-lang/rust/issues/10184.
        self.update(
            rtt.as_micros() as u32,
            |cur_srtt_microseconds, last_update| {
                // An arbitrarily low weight is used when computing the factor
                // to ensure that recent RTT measurements are weighted more
                // heavily.
                let factor = compute_srtt_factor(last_update, 3);
                let new_srtt = (1.0 - factor) * (rtt.as_micros() as f64)
                    + factor * f64::from(cur_srtt_microseconds);
                new_srtt.round() as u32
            },
        );
    }

    /// Records a connection failure for a particular query.
    fn record_failure(&self) {
        self.update(
            Self::FAILURE_PENALTY,
            |cur_srtt_microseconds, _last_update| {
                cur_srtt_microseconds.saturating_add(Self::FAILURE_PENALTY)
            },
        );
    }

    /// Returns the SRTT value after applying a time based decay.
    ///
    /// The decay exponentially decreases the SRTT value. The primary reasons
    /// for applying a downwards decay are twofold:
    ///
    /// 1. It helps distribute query load.
    /// 2. It helps detect positive network changes. For example, decreases in
    ///    latency or a server that has recovered from a failure.
    fn current(&self) -> f64 {
        let srtt = f64::from(self.srtt_microseconds.load(Ordering::Acquire));
        self.last_update.lock().map_or(srtt, |last_update| {
            // In general, if the time between queries is relatively short, then
            // the server ordering algorithm will approximate a spike
            // distribution where the servers with the lowest latencies are
            // chosen much more frequently. Conversely, if the time between
            // queries is relatively long, then the query distribution will be
            // more uniform. A larger weight widens the window in which servers
            // with historically lower latencies will be heavily preferred. On
            // the other hand, a larger weight may also increase the time it
            // takes to recover from a failure or to observe positive changes in
            // latency.
            srtt * compute_srtt_factor(last_update, 180)
        })
    }

    /// Updates the SRTT value.
    ///
    /// If the `last_update` value has not been set, then uses the `default`
    /// value to update the SRTT. Otherwise, invokes the `update_fn` with the
    /// current SRTT value and the `last_update` timestamp.
    fn update(&self, default: u32, update_fn: impl Fn(u32, Instant) -> u32) {
        let last_update = self.last_update.lock().replace(Instant::now());
        let _ = self.srtt_microseconds.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            move |cur_srtt_microseconds| {
                Some(
                    last_update
                        .map_or(default, |last_update| {
                            update_fn(cur_srtt_microseconds, last_update)
                        })
                        .min(Self::MAX_SRTT_MICROS),
                )
            },
        );
    }

    /// Returns the raw SRTT value.
    ///
    /// Prefer to use `decayed_srtt` when ordering name servers.
    #[cfg(all(test, feature = "tokio"))]
    fn as_duration(&self) -> Duration {
        Duration::from_micros(u64::from(self.srtt_microseconds.load(Ordering::Acquire)))
    }

    const FAILURE_PENALTY: u32 = Duration::from_millis(150).as_micros() as u32;
    const MAX_SRTT_MICROS: u32 = Duration::from_secs(5).as_micros() as u32;
}

/// Returns an exponentially weighted value in the range of 0.0 < x < 1.0
///
/// Computes the value using the following formula:
///
/// e<sup>(-t<sub>now</sub> - t<sub>last</sub>) / weight</sup>
///
/// As the duration since the `last_update` approaches the provided `weight`,
/// the returned value decreases.
fn compute_srtt_factor(last_update: Instant, weight: u32) -> f64 {
    let exponent = (-last_update.elapsed().as_secs_f64().max(1.0)) / f64::from(weight);
    exponent.exp()
}

/// State of a connection with a remote NameServer.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum Status {
    /// For some reason the connection failed. For UDP this would generally be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should *not* be entered due to an
    ///  error contained in a Message received from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed = 0,
    /// Initial state, if Edns is not none, then Edns will be requested
    Init = 1,
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established = 2,
}

impl From<Status> for u8 {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn from(val: Status) -> Self {
        val as Self
    }
}

impl From<u8> for Status {
    fn from(val: u8) -> Self {
        match val {
            2 => Self::Established,
            1 => Self::Init,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub(crate) struct ConnectionPolicy {
    pub(crate) disable_udp: bool,
}

impl ConnectionPolicy {
    /// Checks if the given server has any protocols compatible with current policy.
    pub(crate) fn allows_server<P: ConnectionProvider>(&self, server: &NameServer<P>) -> bool {
        server.protocols().any(|p| self.allows_protocol(p))
    }

    /// Select the best pre-existing connection to use.
    ///
    /// This choice is made based on opportunistic encryption policy & probe history,
    /// protocol policy, and the SRTT performance metrics.
    fn select_connection<'a, P: ConnectionProvider>(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        connections: &'a [ConnectionState<P>],
    ) -> Option<&'a ConnectionState<P>> {
        let selected = connections
            .iter()
            .filter(|conn| self.allows_protocol(conn.protocol))
            .min_by(|a, b| self.compare_connections(opportunistic_encryption.is_enabled(), a, b));

        let selected = selected?;

        // If we're using opportunistic encryption and selected a pre-existing unencrypted connection,
        // and have successfully probed on any supported encrypted protocol, we should _not_ reuse the
        // existing connection and instead return `None`. This will result in a new encrypted connection
        // being made to the successfully probed protocol and added to the connection list for future
        // re-use.
        match opportunistic_encryption.is_enabled()
            && !selected.protocol.is_encrypted()
            && encrypted_transport_state.any_recent_success(ip, opportunistic_encryption)
        {
            true => None,
            false => Some(selected),
        }
    }

    /// Select the best connection configuration to use for a new connection.
    ///
    /// This choice is made based on opportunistic encryption policy & probe history,
    /// and protocol policy.
    fn select_connection_config<'a>(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        connection_configs: &'a [ConnectionConfig],
    ) -> Option<&'a ConnectionConfig> {
        connection_configs
            .iter()
            .filter(|c| self.allows_protocol(c.protocol.to_protocol()))
            .min_by(|a, b| {
                self.compare_connection_configs(
                    ip,
                    encrypted_transport_state,
                    opportunistic_encryption,
                    a,
                    b,
                )
            })
    }

    /// Select the first protocol allowed by current policy that uses an encrypted transport.
    fn select_encrypted_connection_config<'a>(
        &self,
        connection_config: &'a [ConnectionConfig],
    ) -> Option<&'a ConnectionConfig> {
        connection_config
            .iter()
            .filter(|c| self.allows_protocol(c.protocol.to_protocol()))
            .find(|c| c.protocol.to_protocol().is_encrypted())
    }

    /// Checks if the given protocol is allowed by current policy.
    fn allows_protocol(&self, protocol: Protocol) -> bool {
        !(self.disable_udp && protocol == Protocol::Udp)
    }

    /// Compare two connections according to policy, protocol, and performance.
    /// If opportunistic encryption is enabled we make an effort to select an encrypted connection.
    fn compare_connections<P: ConnectionProvider>(
        &self,
        opportunistic_encryption: bool,
        a: &ConnectionState<P>,
        b: &ConnectionState<P>,
    ) -> cmp::Ordering {
        // When opportunistic encryption is in-play, we want to consider encrypted
        // connections with the greatest priority.
        if opportunistic_encryption {
            match (a.protocol.is_encrypted(), b.protocol.is_encrypted()) {
                (true, false) => return cmp::Ordering::Less,
                (false, true) => return cmp::Ordering::Greater,
                // When _both_ are encrypted, then decide on ordering based on other properties (like SRTT).
                _ => {}
            }
        }

        match (a.protocol, b.protocol) {
            (ap, bp) if ap == bp => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
            (Protocol::Udp, _) => cmp::Ordering::Less,
            (_, Protocol::Udp) => cmp::Ordering::Greater,
            _ => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
        }
    }

    fn compare_connection_configs(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        a: &ConnectionConfig,
        b: &ConnectionConfig,
    ) -> cmp::Ordering {
        let a_protocol = a.protocol.to_protocol();
        let b_protocol = b.protocol.to_protocol();

        // When opportunistic encryption is in-play, prioritize encrypted protocols
        // that have recent successful connections
        if opportunistic_encryption.is_enabled() {
            let a_recent_enc_success = a_protocol.is_encrypted()
                && encrypted_transport_state.recent_success(
                    ip,
                    a_protocol,
                    opportunistic_encryption,
                );
            let b_recent_enc_success = b_protocol.is_encrypted()
                && encrypted_transport_state.recent_success(
                    ip,
                    b_protocol,
                    opportunistic_encryption,
                );

            match (a_recent_enc_success, b_recent_enc_success) {
                (true, false) => return cmp::Ordering::Less,
                (false, true) => return cmp::Ordering::Greater,
                // When both have recent success or neither do, continue with normal ordering
                _ => {}
            }
        }

        // Default protocol ordering: UDP first, then others
        match (a_protocol, b_protocol) {
            (ap, bp) if ap == bp => cmp::Ordering::Equal,
            (Protocol::Udp, _) => cmp::Ordering::Less,
            (_, Protocol::Udp) => cmp::Ordering::Greater,
            _ => cmp::Ordering::Equal,
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use std::cmp;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::Duration;

    use test_support::subscribe;
    use tokio::net::UdpSocket;
    use tokio::spawn;

    use super::*;
    use crate::config::{ConnectionConfig, ProtocolConfig};
    use crate::connection_provider::TlsConfig;
    use crate::proto::op::{DnsRequest, DnsRequestOptions, Message, Query, ResponseCode};
    use crate::proto::rr::rdata::NULL;
    use crate::proto::rr::{Name, RData, Record, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;

    #[tokio::test]
    async fn test_name_server() {
        subscribe();

        let options = ResolverOpts::default();
        let config = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let name_server = Arc::new(NameServer::new(
            [].into_iter(),
            config,
            &options,
            Arc::new(AtomicU8::default()),
            TokioRuntimeProvider::default(),
        ));

        let cx = Arc::new(PoolContext::new(options, TlsConfig::new().unwrap()));
        let name = Name::parse("www.example.com.", None).unwrap();
        let response = name_server
            .send(
                DnsRequest::from_query(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default(),
                ),
                ConnectionPolicy::default(),
                &cx,
            )
            .await
            .expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn test_failed_name_server() {
        subscribe();

        let options = ResolverOpts {
            timeout: Duration::from_millis(1), // this is going to fail, make it fail fast...
            ..ResolverOpts::default()
        };

        let config = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)));
        let name_server = Arc::new(NameServer::new(
            [],
            config,
            &options,
            Arc::new(AtomicU8::default()),
            TokioRuntimeProvider::default(),
        ));

        let cx = Arc::new(PoolContext::new(options, TlsConfig::new().unwrap()));
        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(
            name_server
                .send(
                    DnsRequest::from_query(
                        Query::query(name.clone(), RecordType::A),
                        DnsRequestOptions::default(),
                    ),
                    ConnectionPolicy::default(),
                    &cx
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn case_randomization_query_preserved() {
        subscribe();

        let provider = TokioRuntimeProvider::default();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let name = Name::from_str("dead.beef.").unwrap();
        let data = b"DEADBEEF";

        spawn({
            let name = name.clone();
            async move {
                let mut buffer = [0_u8; 512];
                let (len, addr) = server.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[0..len]).unwrap();
                let mut response = Message::response(request.id(), request.op_code());
                response.add_queries(request.queries().to_vec());
                response.add_answer(Record::from_rdata(
                    name,
                    0,
                    RData::NULL(NULL::with(data.to_vec())),
                ));
                let response_buffer = response.to_vec().unwrap();
                server.send_to(&response_buffer, addr).await.unwrap();
            }
        });

        let config = NameServerConfig {
            ip: server_addr.ip(),
            trust_negative_responses: true,
            connections: vec![ConnectionConfig {
                port: server_addr.port(),
                protocol: ProtocolConfig::Udp,
                bind_addr: None,
            }],
        };

        let resolver_opts = ResolverOpts {
            case_randomization: true,
            ..Default::default()
        };

        let cx = Arc::new(PoolContext::new(resolver_opts, TlsConfig::new().unwrap()));
        let mut request_options = DnsRequestOptions::default();
        request_options.case_randomization = true;
        let ns = Arc::new(NameServer::new(
            [],
            config,
            &cx.options,
            Arc::new(AtomicU8::default()),
            provider,
        ));
        let response = ns
            .send(
                DnsRequest::from_query(
                    Query::query(name.clone(), RecordType::NULL),
                    request_options,
                ),
                ConnectionPolicy::default(),
                &cx,
            )
            .await
            .unwrap();

        let response_query_name = response.queries().first().unwrap().name();
        assert!(response_query_name.eq_case(&name));
    }

    #[allow(clippy::extra_unused_type_parameters)]
    fn is_send_sync<S: Sync + Send>() -> bool {
        true
    }

    #[test]
    fn stats_are_sync() {
        assert!(is_send_sync::<ConnectionMeta>());
    }

    #[tokio::test(start_paused = true)]
    async fn test_stats_cmp() {
        use std::cmp::Ordering;
        let srtt_a = DecayingSrtt::new(Duration::from_micros(10));
        let srtt_b = DecayingSrtt::new(Duration::from_micros(20));

        // No RTTs or failures have been recorded. The initial SRTTs should be
        // compared.
        assert_eq!(cmp(&srtt_a, &srtt_b), Ordering::Less);

        // Server A was used. Unused server B should now be preferred.
        srtt_a.record(Duration::from_millis(30));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&srtt_a, &srtt_b), Ordering::Greater);

        // Both servers have been used. Server A has a lower SRTT and should be
        // preferred.
        srtt_b.record(Duration::from_millis(50));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&srtt_a, &srtt_b), Ordering::Less);

        // Server A experiences a connection failure, which results in Server B
        // being preferred.
        srtt_a.record_failure();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&srtt_a, &srtt_b), Ordering::Greater);

        // Server A should eventually recover and once again be preferred.
        while cmp(&srtt_a, &srtt_b) != Ordering::Less {
            srtt_b.record(Duration::from_millis(50));
            tokio::time::advance(Duration::from_secs(5)).await;
        }

        srtt_a.record(Duration::from_millis(30));
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(cmp(&srtt_a, &srtt_b), Ordering::Less);
    }

    fn cmp(a: &DecayingSrtt, b: &DecayingSrtt) -> cmp::Ordering {
        a.current().total_cmp(&b.current())
    }

    #[tokio::test(start_paused = true)]
    async fn test_record_rtt() {
        let srtt = DecayingSrtt::new(Duration::from_micros(10));

        let first_rtt = Duration::from_millis(50);
        srtt.record(first_rtt);

        // The first recorded RTT should replace the initial value.
        assert_eq!(srtt.as_duration(), first_rtt);

        tokio::time::advance(Duration::from_secs(3)).await;

        // Subsequent RTTs should factor in previously recorded values.
        srtt.record(Duration::from_millis(100));
        assert_eq!(srtt.as_duration(), Duration::from_micros(81606));
    }

    #[test]
    fn test_record_rtt_maximum_value() {
        let srtt = DecayingSrtt::new(Duration::from_micros(10));

        srtt.record(Duration::MAX);
        // Updates to the SRTT are capped at a maximum value.
        assert_eq!(
            srtt.as_duration(),
            Duration::from_micros(DecayingSrtt::MAX_SRTT_MICROS.into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_record_connection_failure() {
        let srtt = DecayingSrtt::new(Duration::from_micros(10));

        // Verify that the SRTT value is initially replaced with the penalty and
        // subsequent failures result in the penalty being added.
        for failure_count in 1..4 {
            srtt.record_failure();
            assert_eq!(
                srtt.as_duration(),
                Duration::from_micros(
                    DecayingSrtt::FAILURE_PENALTY
                        .checked_mul(failure_count)
                        .expect("checked_mul overflow")
                        .into()
                )
            );
            tokio::time::advance(Duration::from_secs(3)).await;
        }

        // Verify that the `last_update` timestamp was updated for a connection
        // failure and is used in subsequent calculations.
        srtt.record(Duration::from_millis(50));
        assert_eq!(srtt.as_duration(), Duration::from_micros(197152));
    }

    #[test]
    fn test_record_connection_failure_maximum_value() {
        let srtt = DecayingSrtt::new(Duration::from_micros(10));

        let num_failures = (DecayingSrtt::MAX_SRTT_MICROS / DecayingSrtt::FAILURE_PENALTY) + 1;
        for _ in 0..num_failures {
            srtt.record_failure();
        }

        // Updates to the SRTT are capped at a maximum value.
        assert_eq!(
            srtt.as_duration(),
            Duration::from_micros(DecayingSrtt::MAX_SRTT_MICROS.into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_decayed_srtt() {
        let initial_srtt = 10;
        let srtt = DecayingSrtt::new(Duration::from_micros(initial_srtt));

        // No decay should be applied to the initial value.
        assert_eq!(srtt.current() as u32, initial_srtt as u32);

        tokio::time::advance(Duration::from_secs(5)).await;
        srtt.record(Duration::from_millis(100));

        // The decay function should assume a minimum of one second has elapsed
        // since the last update.
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(srtt.current() as u32, 99445);

        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(srtt.current() as u32, 96990);
    }
}

#[cfg(all(test, feature = "__tls"))]
mod opportunistic_enc_tests {
    #[cfg(feature = "metrics")]
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU8;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use futures_util::stream::once;
    use futures_util::{Stream, future};
    #[cfg(feature = "metrics")]
    use metrics::{Key, KeyName, Label, SharedString, Unit, with_local_recorder};
    #[cfg(feature = "metrics")]
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    #[cfg(feature = "metrics")]
    use metrics_util::{CompositeKey, MetricKind};
    use parking_lot::Mutex as SyncMutex;
    use test_support::subscribe;
    use tokio::net::UdpSocket;

    #[cfg(feature = "metrics")]
    use crate::proto::ProtoErrorKind;
    use crate::proto::op::{DnsRequest, DnsResponse, Message, ResponseCode};
    use crate::proto::runtime::iocompat::AsyncIoTokioAsStd;
    use crate::proto::runtime::{RuntimeProvider, Spawn, TokioTime};
    use crate::proto::xfer::Protocol;
    use crate::proto::{DnsHandle, ProtoError};

    use crate::config::{
        ConnectionConfig, NameServerConfig, OpportunisticEncryption, OpportunisticEncryptionConfig,
        ProtocolConfig, ResolverOpts,
    };
    use crate::connection_provider::{ConnectionProvider, TlsConfig};
    use crate::name_server::{ConnectionPolicy, ConnectionState, NameServer};
    use crate::name_server_pool::{NameServerTransportState, PoolContext};

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_disabled() {
        let mut policy = ConnectionPolicy::default();
        let connections = vec![
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let state = NameServerTransportState::default();
        let opp_enc = OpportunisticEncryption::Disabled;

        // When opportunistic encryption is disabled, and disable_udp isn't active,
        // we should select the UDP conn.
        let selected = policy.select_connection(ns_ip, &state, &opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Udp);

        // When opportunistic encryption is disabled, and disable_udp is active,
        // we should select the TCP conn.
        policy.disable_udp = true;
        let selected = policy.select_connection(ns_ip, &state, &opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Tcp);
    }

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_enabled() {
        let policy = ConnectionPolicy::default();
        let connections = [
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
            // Include a pre-existing encrypted protocol connection.
            mock_connection(Protocol::Tls),
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // When opportunistic encryption is enabled, and there is an encrypted connection available,
        // we should always choose it as the most preferred.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Tls);
    }

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_enabled_no_state() {
        let mut policy = ConnectionPolicy::default();
        let connections = [
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
            // No pre-existing encrypted protocol connection is available.
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // When opportunistic encryption is enabled, but there are no encrypted connections available,
        // and we have no probe state, we should select the UDP conn.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Udp);

        // When opportunistic encryption is enabled, but there are no encrypted connections available,
        // and we have no probe state, we should select the TCP conn.
        policy.disable_udp = true;
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Tcp);
    }

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_enabled_failed_probe() {
        let policy = ConnectionPolicy::default();
        let connections = [
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
            // No pre-existing encrypted protocol connection is available.
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // Update the state to reflect that we failed a previous probe attempt.
        state.error_received(
            ns_ip,
            Protocol::Tls,
            &ProtoError::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "nameserver refused TLS connection",
            )),
        );

        // When opportunistic encryption is enabled, but there are no encrypted connections available,
        // and our probe state indicates a failure, we should select the UDP conn.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Udp);
    }

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_enabled_in_progress_probe() {
        let policy = ConnectionPolicy::default();
        let connections = [
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
            // No pre-existing encrypted protocol connection is available.
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // Update the state to reflect that we have an in-progress probe in-flight.
        state.initiate_connection(ns_ip, Protocol::Tls);

        // When opportunistic encryption is enabled, but there are no encrypted connections available,
        // and our probe state indicates an in-flight probe, we should select the UDP conn.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Udp);

        // Update the state to reflect that we completed the connection, but haven't
        // received a response.
        state.complete_connection(ns_ip, Protocol::Tls);

        // In this case we should still select the UDP conn.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Udp);
    }

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_enabled_stale_probe() {
        let policy = ConnectionPolicy::default();
        let connections = [
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
            // No pre-existing encrypted protocol connection is available.
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut state = NameServerTransportState::default();
        let opp_enc_config = OpportunisticEncryptionConfig {
            persistence_period: Duration::from_secs(10),
            ..OpportunisticEncryptionConfig::default()
        };
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: opp_enc_config,
        };

        // Update the state to reflect that we have successfully probed this NS.
        state.complete_connection(ns_ip, Protocol::Tls);
        state.response_received(ns_ip, Protocol::Tls);
        // And then update the last response time to be too stale for consideration.
        let stale_time =
            Instant::now() - opp_enc_config.persistence_period - Duration::from_secs(1);
        state.set_last_response(ns_ip, Protocol::Tls, stale_time);

        // When opportunistic encryption is enabled, but there are no encrypted connections available,
        // and our probe state indicates success that is too stale, we should select an unencrypted
        // connection since the probe is no longer considered recent.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, Protocol::Udp);
    }

    #[tokio::test]
    async fn test_select_connection_opportunistic_enc_enabled_good_probe() {
        let policy = ConnectionPolicy::default();
        let connections = [
            mock_connection(Protocol::Udp),
            mock_connection(Protocol::Tcp),
            // No pre-existing encrypted protocol connection is available.
        ];

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // Update the state to reflect that we have successfully probed this NS within
        // the persistence period and received a response.
        state.complete_connection(ns_ip, Protocol::Tls);
        state.response_received(ns_ip, Protocol::Tls);

        // When opportunistic encryption is enabled, but there are no encrypted connections available,
        // and our probe state indicates a recent enough success, we should return `None` so that
        // we make a new encrypted connection.
        let selected = policy.select_connection(ns_ip, &state, opp_enc, &connections);
        assert!(selected.is_none());
    }

    #[tokio::test]
    async fn test_select_connection_config_opportunistic_enc_disabled() {
        let mut policy = ConnectionPolicy::default();

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let configs = NameServerConfig::opportunistic_encryption(ns_ip).connections;

        let state = NameServerTransportState::default();
        let opp_enc = OpportunisticEncryption::Disabled;

        // When opportunistic encryption is disabled, and disable_udp isn't active,
        // we should select the UDP config.
        let selected = policy.select_connection_config(ns_ip, &state, &opp_enc, &configs);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, ProtocolConfig::Udp);

        // When opportunistic encryption is disabled, and disable_udp is active,
        // we should select the TCP config.
        policy.disable_udp = true;
        let selected = policy.select_connection_config(ns_ip, &state, &opp_enc, &configs);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, ProtocolConfig::Tcp);
    }

    #[tokio::test]
    async fn test_select_connection_config_opportunistic_enc_enabled_no_state() {
        let mut policy = ConnectionPolicy::default();
        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let configs = NameServerConfig::opportunistic_encryption(ns_ip).connections;

        let state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // When opportunistic encryption is enabled, but we have no probe state,
        // we should select the UDP config (default protocol ordering).
        let selected = policy.select_connection_config(ns_ip, &state, opp_enc, &configs);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, ProtocolConfig::Udp);

        // When opportunistic encryption is enabled, but we have no probe state,
        // and disable_udp is active, we should select the TCP config.
        policy.disable_udp = true;
        let selected = policy.select_connection_config(ns_ip, &state, opp_enc, &configs);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, ProtocolConfig::Tcp);
    }

    #[tokio::test]
    async fn test_select_connection_config_opportunistic_enc_enabled_failed_probe() {
        let policy = ConnectionPolicy::default();
        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let configs = NameServerConfig::opportunistic_encryption(ns_ip).connections;

        let mut state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // Update the state to reflect that we failed a previous probe attempt.
        state.error_received(
            ns_ip,
            Protocol::Tls,
            &ProtoError::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "nameserver refused TLS connection",
            )),
        );

        // When opportunistic encryption is enabled, but our probe state indicates a failure,
        // we should select the UDP config.
        let selected = policy.select_connection_config(ns_ip, &state, opp_enc, &configs);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, ProtocolConfig::Udp);
    }

    #[tokio::test]
    async fn test_select_connection_config_opportunistic_enc_enabled_stale_probe() {
        let policy = ConnectionPolicy::default();
        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let configs = NameServerConfig::opportunistic_encryption(ns_ip).connections;

        let mut state = NameServerTransportState::default();
        let opp_enc_config = OpportunisticEncryptionConfig {
            persistence_period: Duration::from_secs(10),
            ..OpportunisticEncryptionConfig::default()
        };
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: opp_enc_config,
        };

        // Update the state to reflect that we have successfully probed this NS.
        state.complete_connection(ns_ip, Protocol::Tls);
        state.response_received(ns_ip, Protocol::Tls);
        // And then update the last response time to be too stale for consideration.
        let stale_time =
            Instant::now() - opp_enc_config.persistence_period - Duration::from_secs(1);
        state.set_last_response(ns_ip, Protocol::Tls, stale_time);

        // When opportunistic encryption is enabled, but our probe state indicates success that is too stale,
        // we should select an unencrypted config since the probe is no longer considered recent.
        let selected = policy.select_connection_config(ns_ip, &state, opp_enc, &configs);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().protocol, ProtocolConfig::Udp);
    }

    #[tokio::test]
    async fn test_select_connection_config_opportunistic_enc_enabled_good_probe() {
        let policy = ConnectionPolicy::default();
        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let configs = NameServerConfig::opportunistic_encryption(ns_ip).connections;

        let mut state = NameServerTransportState::default();
        let opp_enc = &OpportunisticEncryption::Enabled {
            config: OpportunisticEncryptionConfig::default(),
        };

        // Update the state to reflect that we have successfully probed this NS within
        // the persistence period and received a response.
        state.complete_connection(ns_ip, Protocol::Tls);
        state.response_received(ns_ip, Protocol::Tls);

        // When opportunistic encryption is enabled, and our probe state indicates a recent enough success,
        // we should select the encrypted config with highest priority.
        let selected = policy.select_connection_config(ns_ip, &state, opp_enc, &configs);
        assert!(selected.is_some());
        assert!(matches!(
            selected.unwrap().protocol,
            ProtocolConfig::Tls { .. }
        ));
    }

    #[tokio::test]
    async fn test_opportunistic_probe() {
        subscribe();

        // Enable opportunistic encryption
        let cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
            .with_opportunistic_encryption();

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mock_provider = MockProvider::default();
        assert!(
            test_connected_mut_client(ns_ip, 10, Arc::new(cx), &mock_provider)
                .await
                .is_ok()
        );

        let recorded_calls = mock_provider.new_connection_calls();
        // We should have made two new connection calls.
        assert_eq!(recorded_calls.len(), 2);
        let (ips, protocols): (Vec<IpAddr>, Vec<ProtocolConfig>) =
            recorded_calls.into_iter().unzip();
        // All connections should be to the expected NS IP.
        assert!(ips.iter().all(|ip| *ip == ns_ip));
        // We should have made connections for both the UDP protocol, and the encrypted probe protocol.
        let protocols = protocols
            .iter()
            .map(ProtocolConfig::to_protocol)
            .collect::<Vec<_>>();
        assert!(protocols.contains(&Protocol::Udp));
        assert!(protocols.contains(&Protocol::Tls));
    }

    #[tokio::test]
    async fn test_opportunistic_probe_skip_in_progress() {
        subscribe();

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
            .with_opportunistic_encryption();

        // Set up state to show an in-flight connection already initiated
        cx.transport_state()
            .await
            .initiate_connection(ns_ip, Protocol::Tls);

        let mock_provider = MockProvider::default();
        assert!(
            test_connected_mut_client(ns_ip, 10, Arc::new(cx), &mock_provider)
                .await
                .is_ok()
        );

        let recorded_calls = mock_provider.new_connection_calls();
        // We should have made only one connection call (UDP), no probe because one is already in-flight
        assert_eq!(recorded_calls.len(), 1);
        let (ip, protocol) = &recorded_calls[0];
        assert_eq!(*ip, ns_ip);
        assert_eq!(protocol.to_protocol(), Protocol::Udp);
    }

    #[tokio::test]
    async fn test_opportunistic_probe_skip_recent_failure() {
        subscribe();

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
            .with_opportunistic_encryption();

        // Set up state to show a recent failure within the damping period
        cx.transport_state().await.error_received(
            ns_ip,
            Protocol::Tls,
            &ProtoError::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
        );

        let mock_provider = MockProvider::default();
        assert!(
            test_connected_mut_client(ns_ip, 10, Arc::new(cx), &mock_provider)
                .await
                .is_ok()
        );

        let recorded_calls = mock_provider.new_connection_calls();
        // We should have made only one connection call (UDP), no probe due to recent failure
        assert_eq!(recorded_calls.len(), 1);
        let (ip, protocol) = &recorded_calls[0];
        assert_eq!(*ip, ns_ip);
        assert_eq!(protocol.to_protocol(), Protocol::Udp);
    }

    #[tokio::test]
    async fn test_opportunistic_probe_stale_failure() {
        subscribe();

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap());
        let opp_enc_config = OpportunisticEncryptionConfig {
            damping_period: Duration::from_secs(5),
            ..OpportunisticEncryptionConfig::default()
        };
        cx.opportunistic_encryption = OpportunisticEncryption::Enabled {
            config: opp_enc_config,
        };

        // Set up state to show an old failure outside the damping period.
        {
            let mut state = cx.transport_state().await;
            let old_failure_time =
                Instant::now() - opp_enc_config.damping_period - Duration::from_secs(1);
            state.set_failure_time(ns_ip, Protocol::Tls, old_failure_time);
        }

        let mock_provider = MockProvider::default();
        assert!(
            test_connected_mut_client(ns_ip, 10, Arc::new(cx), &mock_provider)
                .await
                .is_ok()
        );

        let recorded_calls = mock_provider.new_connection_calls();
        // We should have made two connection calls (UDP + TLS probe) because the failure is old
        assert_eq!(recorded_calls.len(), 2);
        let protocols = recorded_calls
            .iter()
            .map(|(_, protocol)| protocol.to_protocol())
            .collect::<Vec<_>>();
        assert!(protocols.contains(&Protocol::Udp));
        assert!(protocols.contains(&Protocol::Tls));
    }

    #[tokio::test]
    async fn test_opportunistic_probe_skip_no_budget() {
        subscribe();

        let ns_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let cx = PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
            .with_opportunistic_encryption();
        let mock_provider = MockProvider::default();
        // Set budget to 0 to simulate exhausted probe budget
        assert!(
            test_connected_mut_client(ns_ip, 0, Arc::new(cx), &mock_provider)
                .await
                .is_ok()
        );

        let recorded_calls = mock_provider.new_connection_calls();
        // We should have made only one connection call (UDP), no probe due to exhausted budget
        assert_eq!(recorded_calls.len(), 1);
        let (ip, protocol) = &recorded_calls[0];
        assert_eq!(*ip, ns_ip);
        assert_eq!(protocol.to_protocol(), Protocol::Udp);
    }

    fn mock_connection(protocol: Protocol) -> ConnectionState<MockProvider> {
        ConnectionState::new(MockClientHandle, protocol)
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_opportunistic_probe_metrics_success() {
        subscribe();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                assert!(
                    test_connected_mut_client(
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        10,
                        Arc::new(
                            PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
                                .with_opportunistic_encryption(),
                        ),
                        &MockProvider::default(),
                    )
                    .await
                    .is_ok()
                );
            });
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        // We should have registered 1 TLS protocol probe attempt.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_attempts_total", 1);

        // We should have registered 1 TLS protocol probe success.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_successes_total", 1);

        // We should have registered 0 TLS protocol probe errors.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_errors_total", 0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_opportunistic_probe_metrics_budget_exhausted() {
        subscribe();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                assert!(
                    test_connected_mut_client(
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        // Set budget to 0 to simulate exhausted probe budget
                        0,
                        Arc::new(
                            PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
                                .with_opportunistic_encryption(),
                        ),
                        &MockProvider::default(),
                    )
                    .await
                    .is_ok()
                );
            });
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        // The budget metric should confirm that there's no budget.
        let (unit_opt, _, value) = map
            .get(&CompositeKey::new(
                MetricKind::Gauge,
                Key::from_name("hickory_resolver_probe_budget_total"),
            ))
            .unwrap();
        assert_eq!(unit_opt, &Some(Unit::Count));
        if let DebugValue::Gauge(gauge_val) = value {
            assert_eq!(gauge_val.into_inner(), 0.0);
        } else {
            panic!("expected gauge value, got {:?}", value);
        }

        // We should not have registered a probe attempt.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_attempts_total", 0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_opportunistic_probe_metrics_connection_error() {
        subscribe();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let _ = test_connected_mut_client(
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    10,
                    Arc::new(
                        PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
                            .with_opportunistic_encryption(),
                    ),
                    // Configure a mock provider that always produces an error when new connections are requested.
                    &MockProvider {
                        new_connection_error: Some(ProtoError::from(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "connection refused",
                        ))),
                        ..MockProvider::default()
                    },
                )
                .await;
            });
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        // We should have registered 1 TLS protocol probe attempt.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_attempts_total", 1);

        // We should have registered 1 TLS protocol probe error.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_errors_total", 1);

        // We shouldn't have registered any TLS protocol probe successes due to the
        // mock new connection error.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_successes_total", 0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_opportunistic_probe_metrics_connection_timeout_error() {
        subscribe();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let _ = test_connected_mut_client(
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    10,
                    Arc::new(
                        PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
                            .with_opportunistic_encryption(),
                    ),
                    // Configure a mock provider that always produces a Timeout error when new connections are requested.
                    &MockProvider {
                        new_connection_error: Some(ProtoError::from(ProtoErrorKind::Timeout)),
                        ..MockProvider::default()
                    },
                )
                .await;
            });
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        // We should have registered 1 TLS protocol probe attempt.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_attempts_total", 1);

        // We should have registered 1 TLS protocol probe timeout.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_timeouts_total", 1);

        // We shouldn't have registered a more general probe error.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_errors_total", 0);

        // We shouldn't have registered any TLS protocol probe successes due to the
        // mock new connection error.
        assert_tls_counter_eq(&map, "hickory_resolver_probe_successes_total", 0);
    }

    /// Construct a nameserver appropriate for opportunistic encryption and assert connected_mut_client
    /// returns Ok.
    ///
    /// Behind the scenes this may provoke probing behaviour that the calling test can observe via
    /// the `MockProvider`'s recorded calls.
    async fn test_connected_mut_client(
        ns_ip: IpAddr,
        probe_budget: u8,
        cx: Arc<PoolContext>,
        provider: &MockProvider,
    ) -> Result<(), ProtoError> {
        let name_server = NameServer::new(
            [].into_iter(),
            NameServerConfig::opportunistic_encryption(ns_ip),
            &ResolverOpts::default(),
            Arc::new(AtomicU8::new(probe_budget)),
            provider.clone(),
        );

        name_server
            .connected_mut_client(ConnectionPolicy::default(), &cx)
            .await
            .map(|_| ())
    }

    /// asserts that the `map` contains a counter metric with the specified `name` reporting
    /// the `expected `value.
    ///
    /// A protocol=tls label is automatically applied by the helper.
    #[cfg(feature = "metrics")]
    #[allow(clippy::mutable_key_type)]
    fn assert_tls_counter_eq(
        map: &HashMap<CompositeKey, (Option<Unit>, Option<SharedString>, DebugValue)>,
        name: impl Into<KeyName>,
        expected: u64,
    ) {
        let (unit_opt, _, value) = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                Key::from_parts(name, vec![Label::new("protocol", "tls")]),
            ))
            .unwrap();
        assert_eq!(unit_opt, &Some(Unit::Count));
        assert_eq!(value, &DebugValue::Counter(expected));
    }

    /// `MockProvider` is a `ConnectionProvider` that uses a synchronous runtime provider.
    ///
    /// It also tracks calls to `new_connection`, exposing the arguments provided as
    /// `new_connection_calls` for test to interrogate. The optional `new_connection_error`
    /// `ProtoError` can be set to have `new_connection()` return a future that will error
    /// when polled, mocking a connection failure.
    #[derive(Clone)]
    struct MockProvider {
        runtime: MockSyncRuntimeProvider,
        new_connection_calls: Arc<SyncMutex<Vec<(IpAddr, ProtocolConfig)>>>,
        new_connection_error: Option<ProtoError>,
    }

    impl MockProvider {
        fn new_connection_calls(&self) -> Vec<(IpAddr, ProtocolConfig)> {
            self.new_connection_calls.lock().clone()
        }
    }

    impl ConnectionProvider for MockProvider {
        type Conn = MockClientHandle;
        type FutureConn = Pin<Box<dyn Send + Future<Output = Result<Self::Conn, ProtoError>>>>;
        type RuntimeProvider = MockSyncRuntimeProvider;

        fn new_connection(
            &self,
            ip: IpAddr,
            config: &ConnectionConfig,
            _cx: &PoolContext,
        ) -> Result<Self::FutureConn, std::io::Error> {
            self.new_connection_calls
                .lock()
                .push((ip, config.protocol.clone()));

            Ok(Box::pin(future::ready(match &self.new_connection_error {
                Some(err) => Err(err.clone()),
                None => Ok(MockClientHandle),
            })))
        }

        fn runtime_provider(&self) -> &Self::RuntimeProvider {
            &self.runtime
        }
    }

    impl Default for MockProvider {
        fn default() -> Self {
            Self {
                runtime: MockSyncRuntimeProvider,
                new_connection_calls: Arc::new(SyncMutex::new(Vec::new())),
                new_connection_error: None,
            }
        }
    }

    /// `MockClientHandle` is a `DnsHandle` that uses a synchronous runtime provider.
    ///
    /// It's `send` method always returns a `NoError` response when polled, simulating a
    /// successful DNS request exchange.
    #[derive(Clone, Default)]
    struct MockClientHandle;

    impl DnsHandle for MockClientHandle {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;
        type Runtime = MockSyncRuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            let mut response = Message::response(request.id(), request.op_code());
            response.set_response_code(ResponseCode::NoError);
            response.add_queries(request.queries().iter().cloned());
            Box::pin(once(future::ready(Ok(
                DnsResponse::from_message(response).unwrap()
            ))))
        }
    }

    /// `MockSyncRuntimeProvider` is a `RuntimeProvider` that creates `MockSyncHandle` instances.
    ///
    /// Trait methods other than `create_handle` are not implemented.
    #[derive(Clone)]
    struct MockSyncRuntimeProvider;

    impl RuntimeProvider for MockSyncRuntimeProvider {
        type Handle = MockSyncHandle;
        type Timer = TokioTime;
        type Udp = UdpSocket;
        type Tcp = AsyncIoTokioAsStd<tokio::net::TcpStream>;
        type Tls = AsyncIoTokioAsStd<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

        fn create_handle(&self) -> Self::Handle {
            MockSyncHandle
        }

        #[allow(clippy::unimplemented)]
        fn connect_tcp(
            &self,
            _server_addr: std::net::SocketAddr,
            _bind_addr: Option<std::net::SocketAddr>,
            _timeout: Option<Duration>,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Tcp>> + Send>> {
            unimplemented!();
        }

        #[allow(clippy::unimplemented)]
        fn connect_tls(
            &self,
            _tcp_stream: Self::Tcp,
            _server_name: rustls::pki_types::ServerName<'static>,
            _client_config: std::sync::Arc<rustls::ClientConfig>,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Tls>> + Send>> {
            unimplemented!();
        }

        #[allow(clippy::unimplemented)]
        fn bind_udp(
            &self,
            _local_addr: std::net::SocketAddr,
            _server_addr: std::net::SocketAddr,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::Udp>> + Send>> {
            unimplemented!();
        }
    }

    /// `MockSyncHandle` is a `Spawn` implementation that polls task futures synchronously.
    ///
    /// Provided futures will be polled until completion, allowing tests to avoid needing to
    /// coordinate with background tasks to determine their completion state.
    #[derive(Clone)]
    struct MockSyncHandle;

    impl Spawn for MockSyncHandle {
        fn spawn_bg<F>(&mut self, future: F)
        where
            F: Future<Output = Result<(), ProtoError>> + Send + 'static,
        {
            // Instead of spawning the future as a background task, poll it synchronously
            // until completion.
            let waker = futures_util::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            let mut future = Box::pin(future);

            loop {
                match future.as_mut().poll(&mut context) {
                    Poll::Ready(_) => break,
                    Poll::Pending => continue,
                }
            }
        }
    }
}
