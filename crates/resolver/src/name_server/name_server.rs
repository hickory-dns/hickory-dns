// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Debug, Formatter};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
#[cfg(not(test))]
use std::time::{Duration, Instant};

use futures_util::lock::Mutex as AsyncMutex;
use futures_util::stream::{Stream, once};
use parking_lot::Mutex as SyncMutex;
#[cfg(test)]
use tokio::time::{Duration, Instant};
use tracing::debug;

use crate::config::{NameServerConfig, ResolverOpts};
use crate::name_server::connection_provider::ConnectionProvider;
use crate::proto::{
    NoRecords, ProtoError, ProtoErrorKind,
    op::ResponseCode,
    xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer},
};

/// This struct is used to create `DnsHandle` with the help of `P`.
#[derive(Clone)]
pub struct NameServer<P: ConnectionProvider> {
    inner: Arc<NameServerState<P>>,
}

impl<P: ConnectionProvider> NameServer<P> {
    /// Construct a new Nameserver with the configuration and options. The connection provider will create UDP and TCP sockets
    pub fn new(
        config: NameServerConfig,
        options: Arc<ResolverOpts>,
        connection_provider: P,
    ) -> Self {
        Self {
            inner: Arc::new(NameServerState::new(
                config,
                options,
                None,
                connection_provider,
            )),
        }
    }

    #[doc(hidden)]
    pub fn from_conn(
        config: NameServerConfig,
        options: Arc<ResolverOpts>,
        client: P::Conn,
        connection_provider: P,
    ) -> Self {
        Self {
            inner: Arc::new(NameServerState::new(
                config,
                options,
                Some(client),
                connection_provider,
            )),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn is_connected(&self) -> bool {
        use ConnectionState::*;
        match (self.inner.state(), self.inner.client.try_lock()) {
            (Established | Init, Some(client)) => client.is_some(),
            (Failed, _) => false,
            // assuming that if someone has it locked it will be or is connected
            (_, None) => true,
        }
    }

    pub(super) fn decayed_srtt(&self) -> f64 {
        self.inner.stats.decayed_srtt()
    }
}

impl<P: ConnectionProvider> DnsHandle for NameServer<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn is_verifying_dnssec(&self) -> bool {
        self.inner.options.validate
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send(&self, request: DnsRequest) -> Self::Response {
        let this = self.clone();
        // if state is failed, return future::err(), unless retry delay expired..
        Box::pin(once(this.inner.send(request)))
    }
}

impl<P: ConnectionProvider> Debug for NameServer<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "config: {:?}, options: {:?}",
            self.inner.config, self.inner.options
        )
    }
}

struct NameServerState<P: ConnectionProvider> {
    config: NameServerConfig,
    options: Arc<ResolverOpts>,
    client: AsyncMutex<Option<P::Conn>>,
    conn_state: AtomicU8,
    stats: NameServerStats,
    connection_provider: P,
}

impl<P: ConnectionProvider> NameServerState<P> {
    fn new(
        config: NameServerConfig,
        options: Arc<ResolverOpts>,
        client: Option<P::Conn>,
        connection_provider: P,
    ) -> Self {
        Self {
            config,
            options,
            client: AsyncMutex::new(client),
            conn_state: AtomicU8::new(ConnectionState::Init.into()),
            stats: NameServerStats::default(),
            connection_provider,
        }
    }

    async fn send(self: Arc<Self>, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
        let client = self.connected_mut_client().await?;
        let now = Instant::now();
        let response = client.send(request).first_answer().await;
        let rtt = now.elapsed();

        match response {
            Ok(response) => {
                // First evaluate if the message succeeded.
                let result =
                    ProtoError::from_response(response, self.config.trust_negative_responses);
                self.stats.record(rtt, &result);
                let response = result?;

                // take the remote edns options and store them
                self.set_state(ConnectionState::Established);

                Ok(response)
            }
            Err(error) => {
                debug!(config = ?self.config, "name_server connection failure: {}", error);

                // this transitions the state to failure
                self.set_state(ConnectionState::Failed);

                // record the failure
                self.stats.record_connection_failure();

                // These are connection failures, not lookup failures, that is handled in the resolver layer
                Err(error)
            }
        }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection
    async fn connected_mut_client(&self) -> Result<P::Conn, ProtoError> {
        let mut client = self.client.lock().await;

        // if this is in a failure state
        if self.state() == ConnectionState::Failed || client.is_none() {
            debug!("reconnecting: {:?}", self.config);

            self.set_state(ConnectionState::Init);

            let new_client = Box::pin(
                self.connection_provider
                    .new_connection(&self.config, &self.options)?,
            )
            .await?;

            // establish a new connection
            *client = Some(new_client);
        } else {
            debug!("existing connection: {:?}", self.config);
        }

        Ok((*client)
            .clone()
            .expect("bad state, client should be connected"))
    }

    fn set_state(&self, conn_state: ConnectionState) {
        self.conn_state.store(conn_state.into(), Ordering::Release);
    }

    fn state(&self) -> ConnectionState {
        ConnectionState::from(self.conn_state.load(Ordering::Acquire))
    }
}

struct NameServerStats {
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
    last_update: Arc<SyncMutex<Option<Instant>>>,
}

impl NameServerStats {
    fn new(initial_srtt: Duration) -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(initial_srtt.as_micros() as u32),
            last_update: Arc::new(SyncMutex::new(None)),
        }
    }

    /// Records the measured `rtt` for a particular result.
    ///
    /// Tries to guess if the result was a failure that should penalize the expected RTT.
    fn record(&self, rtt: Duration, result: &Result<DnsResponse, ProtoError>) {
        let error = match result {
            Ok(_) => {
                self.record_rtt(rtt);
                return;
            }
            Err(err) => err,
        };

        use ResponseCode::*;
        match error.kind() {
            ProtoErrorKind::NoRecordsFound(NoRecords { response_code, .. }) => {
                match response_code {
                    ServFail | Refused => self.record_connection_failure(),
                    _ => self.record_rtt(rtt),
                }
            }
            ProtoErrorKind::Busy
            | ProtoErrorKind::Io(_)
            | ProtoErrorKind::Timeout
            | ProtoErrorKind::RequestRefused => self.record_connection_failure(),
            #[cfg(feature = "__quic")]
            ProtoErrorKind::QuinnConfigError(_)
            | ProtoErrorKind::QuinnConnect(_)
            | ProtoErrorKind::QuinnConnection(_)
            | ProtoErrorKind::QuinnTlsConfigError(_) => self.record_connection_failure(),
            #[cfg(feature = "__tls")]
            ProtoErrorKind::RustlsError(_) => self.record_connection_failure(),
            ProtoErrorKind::NoError => self.record_rtt(rtt),
            _ => {}
        }
    }

    fn record_rtt(&self, rtt: Duration) {
        // If the cast on the result does overflow (it shouldn't), then the
        // value is saturated to u32::MAX, which is above the `MAX_SRTT_MICROS`
        // limit (meaning that any potential overflow is inconsequential).
        // See https://github.com/rust-lang/rust/issues/10184.
        self.update_srtt(
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
    fn record_connection_failure(&self) {
        self.update_srtt(
            Self::CONNECTION_FAILURE_PENALTY,
            |cur_srtt_microseconds, _last_update| {
                cur_srtt_microseconds.saturating_add(Self::CONNECTION_FAILURE_PENALTY)
            },
        );
    }

    /// Returns the raw SRTT value.
    ///
    /// Prefer to use `decayed_srtt` when ordering name servers.
    #[cfg(all(test, feature = "tokio"))]
    fn srtt(&self) -> Duration {
        Duration::from_micros(u64::from(self.srtt_microseconds.load(Ordering::Acquire)))
    }

    /// Returns the SRTT value after applying a time based decay.
    ///
    /// The decay exponentially decreases the SRTT value. The primary reasons
    /// for applying a downwards decay are twofold:
    ///
    /// 1. It helps distribute query load.
    /// 2. It helps detect positive network changes. For example, decreases in
    ///    latency or a server that has recovered from a failure.
    fn decayed_srtt(&self) -> f64 {
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
    fn update_srtt(&self, default: u32, update_fn: impl Fn(u32, Instant) -> u32) {
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

    const CONNECTION_FAILURE_PENALTY: u32 = Duration::from_millis(150).as_micros() as u32;
    const MAX_SRTT_MICROS: u32 = Duration::from_secs(5).as_micros() as u32;
}

impl Default for NameServerStats {
    fn default() -> Self {
        // Initialize the SRTT to a randomly generated value that represents a
        // very low RTT. Such a value helps ensure that each server is attempted
        // early.
        Self::new(Duration::from_micros(rand::random_range(1..32)))
    }
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
enum ConnectionState {
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

impl From<ConnectionState> for u8 {
    /// used for ordering purposes. The highest priority is placed on open connections
    fn from(val: ConnectionState) -> Self {
        val as Self
    }
}

impl From<u8> for ConnectionState {
    fn from(val: u8) -> Self {
        match val {
            2 => Self::Established,
            1 => Self::Init,
            _ => Self::Failed,
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use std::cmp;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    use test_support::subscribe;
    use tokio::net::UdpSocket;
    use tokio::spawn;

    use super::*;
    use crate::config::ProtocolConfig;
    use crate::name_server::GenericNameServer;
    use crate::name_server::connection_provider::TokioConnectionProvider;
    use crate::proto::op::{Message, Query, ResponseCode};
    use crate::proto::rr::rdata::NULL;
    use crate::proto::rr::{Name, RData, Record, RecordType};
    use crate::proto::xfer::{DnsHandle, DnsRequestOptions, FirstAnswer};

    #[tokio::test]
    async fn test_name_server() {
        subscribe();

        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: ProtocolConfig::Udp,
            trust_negative_responses: false,
            bind_addr: None,
        };
        let name_server = GenericNameServer::new(
            config,
            Arc::new(ResolverOpts::default()),
            TokioConnectionProvider::default(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = name_server
            .lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
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
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)), 252),
            protocol: ProtocolConfig::Udp,
            trust_negative_responses: false,
            bind_addr: None,
        };
        let name_server = GenericNameServer::new(
            config,
            Arc::new(options),
            TokioConnectionProvider::default(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(
            name_server
                .lookup(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default(),
                )
                .first_answer()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn case_randomization_query_preserved() {
        subscribe();

        let provider = TokioConnectionProvider::default();
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

        let config = NameServerConfig::new(server_addr, ProtocolConfig::Udp);
        let resolver_opts = ResolverOpts {
            case_randomization: true,
            ..Default::default()
        };
        let mut request_options = DnsRequestOptions::default();
        request_options.case_randomization = true;
        let ns = NameServer::new(config, Arc::new(resolver_opts), provider);

        let stream = ns.lookup(
            Query::query(name.clone(), RecordType::NULL),
            request_options,
        );
        let response = stream.first_answer().await.unwrap();

        let response_query_name = response.queries().first().unwrap().name();
        assert!(response_query_name.eq_case(&name));
    }

    #[allow(clippy::extra_unused_type_parameters)]
    fn is_send_sync<S: Sync + Send>() -> bool {
        true
    }

    #[test]
    fn stats_are_sync() {
        assert!(is_send_sync::<NameServerStats>());
    }

    #[tokio::test(start_paused = true)]
    async fn test_stats_cmp() {
        use std::cmp::Ordering;
        let server_a = NameServerStats::new(Duration::from_micros(10));
        let server_b = NameServerStats::new(Duration::from_micros(20));

        // No RTTs or failures have been recorded. The initial SRTTs should be
        // compared.
        assert_eq!(cmp(&server_a, &server_b), Ordering::Less);

        // Server A was used. Unused server B should now be preferred.
        server_a.record_rtt(Duration::from_millis(30));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Greater);

        // Both servers have been used. Server A has a lower SRTT and should be
        // preferred.
        server_b.record_rtt(Duration::from_millis(50));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Less);

        // Server A experiences a connection failure, which results in Server B
        // being preferred.
        server_a.record_connection_failure();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Greater);

        // Server A should eventually recover and once again be preferred.
        while cmp(&server_a, &server_b) != Ordering::Less {
            server_b.record_rtt(Duration::from_millis(50));
            tokio::time::advance(Duration::from_secs(5)).await;
        }

        server_a.record_rtt(Duration::from_millis(30));
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Less);
    }

    fn cmp(a: &NameServerStats, b: &NameServerStats) -> cmp::Ordering {
        a.decayed_srtt().total_cmp(&b.decayed_srtt())
    }

    #[tokio::test(start_paused = true)]
    async fn test_record_rtt() {
        let server = NameServerStats::new(Duration::from_micros(10));

        let first_rtt = Duration::from_millis(50);
        server.record_rtt(first_rtt);

        // The first recorded RTT should replace the initial value.
        assert_eq!(server.srtt(), first_rtt);

        tokio::time::advance(Duration::from_secs(3)).await;

        // Subsequent RTTs should factor in previously recorded values.
        server.record_rtt(Duration::from_millis(100));
        assert_eq!(server.srtt(), Duration::from_micros(81606));
    }

    #[test]
    fn test_record_rtt_maximum_value() {
        let server = NameServerStats::new(Duration::from_micros(10));

        server.record_rtt(Duration::MAX);
        // Updates to the SRTT are capped at a maximum value.
        assert_eq!(
            server.srtt(),
            Duration::from_micros(NameServerStats::MAX_SRTT_MICROS.into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_record_connection_failure() {
        let server = NameServerStats::new(Duration::from_micros(10));

        // Verify that the SRTT value is initially replaced with the penalty and
        // subsequent failures result in the penalty being added.
        for failure_count in 1..4 {
            server.record_connection_failure();
            assert_eq!(
                server.srtt(),
                Duration::from_micros(
                    NameServerStats::CONNECTION_FAILURE_PENALTY
                        .checked_mul(failure_count)
                        .expect("checked_mul overflow")
                        .into()
                )
            );
            tokio::time::advance(Duration::from_secs(3)).await;
        }

        // Verify that the `last_update` timestamp was updated for a connection
        // failure and is used in subsequent calculations.
        server.record_rtt(Duration::from_millis(50));
        assert_eq!(server.srtt(), Duration::from_micros(197152));
    }

    #[test]
    fn test_record_connection_failure_maximum_value() {
        let server = NameServerStats::new(Duration::from_micros(10));

        let num_failures =
            (NameServerStats::MAX_SRTT_MICROS / NameServerStats::CONNECTION_FAILURE_PENALTY) + 1;
        for _ in 0..num_failures {
            server.record_connection_failure();
        }

        // Updates to the SRTT are capped at a maximum value.
        assert_eq!(
            server.srtt(),
            Duration::from_micros(NameServerStats::MAX_SRTT_MICROS.into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_decayed_srtt() {
        let initial_srtt = 10;
        let server = NameServerStats::new(Duration::from_micros(initial_srtt));

        // No decay should be applied to the initial value.
        assert_eq!(server.decayed_srtt() as u32, initial_srtt as u32);

        tokio::time::advance(Duration::from_secs(5)).await;
        server.record_rtt(Duration::from_millis(100));

        // The decay function should assume a minimum of one second has elapsed
        // since the last update.
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(server.decayed_srtt() as u32, 99445);

        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(server.decayed_srtt() as u32, 96990);
    }
}
