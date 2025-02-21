// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::{
    Arc,
    atomic::{self, AtomicU32},
};

use parking_lot::Mutex;

#[cfg(not(test))]
use std::time::{Duration, Instant};
#[cfg(test)]
use tokio::time::{Duration, Instant};

pub(crate) struct NameServerStats {
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
    last_update: Arc<Mutex<Option<Instant>>>,
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

impl NameServerStats {
    const CONNECTION_FAILURE_PENALTY: u32 = Duration::from_millis(150).as_micros() as u32;
    const MAX_SRTT_MICROS: u32 = Duration::from_secs(5).as_micros() as u32;

    pub(crate) fn new(initial_srtt: Duration) -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(initial_srtt.as_micros() as u32),
            last_update: Arc::new(Mutex::new(None)),
        }
    }

    /// Records the measured `rtt` for a particular query.
    pub(crate) fn record_rtt(&self, rtt: Duration) {
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
    pub(crate) fn record_connection_failure(&self) {
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
    #[cfg(test)]
    fn srtt(&self) -> Duration {
        Duration::from_micros(u64::from(
            self.srtt_microseconds.load(atomic::Ordering::Acquire),
        ))
    }

    /// Returns the SRTT value after applying a time based decay.
    ///
    /// The decay exponentially decreases the SRTT value. The primary reasons
    /// for applying a downwards decay are twofold:
    ///
    /// 1. It helps distribute query load.
    /// 2. It helps detect positive network changes. For example, decreases in
    ///    latency or a server that has recovered from a failure.
    pub(crate) fn decayed_srtt(&self) -> f64 {
        let srtt = f64::from(self.srtt_microseconds.load(atomic::Ordering::Acquire));
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
            atomic::Ordering::SeqCst,
            atomic::Ordering::SeqCst,
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
}

#[cfg(test)]
#[allow(clippy::extra_unused_type_parameters)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    fn is_send_sync<S: Sync + Send>() -> bool {
        true
    }

    #[test]
    fn stats_are_sync() {
        assert!(is_send_sync::<NameServerStats>());
    }

    #[tokio::test(start_paused = true)]
    async fn test_stats_cmp() {
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

    fn cmp(a: &NameServerStats, b: &NameServerStats) -> Ordering {
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
