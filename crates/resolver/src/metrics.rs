// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Metrics related to resolver and recursive resolver operations

/// Metrics for the optional recursive resolver feature
#[cfg(feature = "recursor")]
pub mod recursor {
    use metrics::{Counter, Unit, counter, describe_counter};

    #[derive(Clone)]
    pub(crate) struct RecursorMetrics {
        pub(crate) cache_hit_counter: Counter,
        pub(crate) cache_miss_counter: Counter,
        pub(crate) outgoing_query_counter: Counter,
    }

    impl RecursorMetrics {
        pub(crate) fn new() -> Self {
            let cache_hit_counter = counter!(CACHE_HIT_TOTAL);
            describe_counter!(
                CACHE_HIT_TOTAL,
                Unit::Count,
                "Number of recursive requests answered from the cache."
            );
            let cache_miss_counter = counter!(CACHE_MISS_TOTAL);
            describe_counter!(
                CACHE_MISS_TOTAL,
                Unit::Count,
                "Number of recursive requests that could not be answered from the cache."
            );
            let outgoing_query_counter = counter!(OUTGOING_QUERIES_TOTAL);
            describe_counter!(
                OUTGOING_QUERIES_TOTAL,
                Unit::Count,
                "Number of outgoing queries made during resolution."
            );
            Self {
                cache_hit_counter,
                cache_miss_counter,
                outgoing_query_counter,
            }
        }
    }

    /// Number of recursive requests answered from the cache.
    pub const CACHE_HIT_TOTAL: &str = "hickory_recursor_cache_hit_total";

    /// Number of recursive requests that could not be answered from the cache.
    pub const CACHE_MISS_TOTAL: &str = "hickory_recursor_cache_miss_total";

    /// Number of outgoing queries made during resolution.
    pub const OUTGOING_QUERIES_TOTAL: &str = "hickory_recursor_outgoing_queries_total";
}

/// Metrics for the optional resolver opportunistic encryption feature
#[cfg(any(feature = "__tls", feature = "__quic"))]
pub mod opportunistic_encryption {
    use std::time::Duration;

    use metrics::{
        Counter, Gauge, Histogram, Unit, counter, describe_counter, describe_gauge,
        describe_histogram, gauge, histogram,
    };
    use tracing::warn;

    use hickory_net::{NetError, xfer::Protocol};

    #[derive(Clone)]
    pub(crate) struct ProbeMetrics {
        pub(crate) probe_budget: Gauge,
        #[cfg(feature = "__tls")]
        tls_probe_metrics: ProbeProtocolMetrics,
        #[cfg(feature = "__quic")]
        quic_probe_metrics: ProbeProtocolMetrics,
    }

    impl ProbeMetrics {
        pub(crate) fn increment_attempts(&self, proto: Protocol) {
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

        pub(crate) fn increment_errors(&self, proto: Protocol, err: &NetError) {
            match (&err, proto) {
                #[cfg(feature = "__tls")]
                (NetError::Timeout, Protocol::Tls) => {
                    self.tls_probe_metrics.probe_timeouts.increment(1)
                }
                #[cfg(feature = "__tls")]
                (_, Protocol::Tls) => self.tls_probe_metrics.probe_errors.increment(1),
                #[cfg(feature = "__quic")]
                (NetError::Timeout, Protocol::Quic) => {
                    self.quic_probe_metrics.probe_timeouts.increment(1)
                }
                #[cfg(feature = "__quic")]
                (_, Protocol::Quic) => self.quic_probe_metrics.probe_errors.increment(1),
                _ => {
                    warn!("probe protocol {proto} not supported for metrics");
                }
            }
        }

        pub(crate) fn increment_successes(&self, proto: Protocol) {
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

        pub(crate) fn record_probe_duration(&self, proto: Protocol, duration: Duration) {
            match proto {
                #[cfg(feature = "__tls")]
                Protocol::Tls => self.tls_probe_metrics.probe_duration.record(duration),
                #[cfg(feature = "__quic")]
                Protocol::Quic => self.tls_probe_metrics.probe_duration.record(duration),
                _ => {
                    warn!("probe protocol {proto} not supported for metrics");
                }
            }
        }
    }

    impl Default for ProbeMetrics {
        fn default() -> Self {
            describe_gauge!(
                PROBE_BUDGET_TOTAL,
                Unit::Count,
                "Count of remaining opportunistic encrypted name server probe requests allowed by budget."
            );
            let probe_budget = gauge!(PROBE_BUDGET_TOTAL);

            Self {
                #[cfg(feature = "__tls")]
                tls_probe_metrics: ProbeProtocolMetrics::new(Protocol::Tls),
                #[cfg(feature = "__quic")]
                quic_probe_metrics: ProbeProtocolMetrics::new(Protocol::Quic),
                probe_budget,
            }
        }
    }

    #[derive(Clone)]
    struct ProbeProtocolMetrics {
        probe_attempts: Counter,
        probe_errors: Counter,
        probe_timeouts: Counter,
        probe_successes: Counter,
        probe_duration: Histogram,
    }

    impl ProbeProtocolMetrics {
        fn new(protocol: Protocol) -> Self {
            describe_counter!(
                PROBE_ATTEMPTS_TOTAL,
                Unit::Count,
                "Number of opportunistic encrypted name server probe requests attempted."
            );
            let probe_attempts = counter!(PROBE_ATTEMPTS_TOTAL, "protocol" => protocol.to_string());

            describe_counter!(
                PROBE_ERRORS_TOTAL,
                Unit::Count,
                "Number of opportunistic encrypted name server probe requests that failed due to an error."
            );
            let probe_errors = counter!(PROBE_ERRORS_TOTAL, "protocol" => protocol.to_string());

            describe_counter!(
                PROBE_TIMEOUTS_TOTAL,
                Unit::Count,
                "Number of opportunistic encrypted name server probe requests that failed due to a timeout."
            );
            let probe_timeouts = counter!(PROBE_TIMEOUTS_TOTAL, "protocol" => protocol.to_string());

            describe_counter!(
                PROBE_SUCCESSES_TOTAL,
                Unit::Count,
                "Number of opportunistic encrypted name server probe requests that succeeded"
            );
            let probe_successes =
                counter!(PROBE_SUCCESSES_TOTAL, "protocol" => protocol.to_string());

            describe_histogram!(
                PROBE_DURATION_SECONDS,
                Unit::Seconds,
                "Duration of opportunistic encryption probe request"
            );
            let probe_duration =
                histogram!(PROBE_DURATION_SECONDS, "protocol" => protocol.to_string());

            Self {
                probe_attempts,
                probe_errors,
                probe_timeouts,
                probe_successes,
                probe_duration,
            }
        }
    }

    /// Count of remaining opportunistic encrypted name server probe requests allowed by budget.
    pub const PROBE_BUDGET_TOTAL: &str = "hickory_resolver_probe_budget_total";

    /// Number of opportunistic encrypted name server probe requests attempted.
    pub const PROBE_ATTEMPTS_TOTAL: &str = "hickory_resolver_probe_attempts_total";

    /// Number of opportunistic encrypted name server probe requests that failed due to an error.
    pub const PROBE_ERRORS_TOTAL: &str = "hickory_resolver_probe_errors_total";

    /// Number of opportunistic encrypted name server probe requests that failed due to a timeout.
    pub const PROBE_TIMEOUTS_TOTAL: &str = "hickory_resolver_probe_timeouts_total";

    /// Number of opportunistic encrypted name server probe requests that succeeded.
    pub const PROBE_SUCCESSES_TOTAL: &str = "hickory_resolver_probe_successes_total";

    /// Duration of opportunistic encryption probe request.
    pub const PROBE_DURATION_SECONDS: &str = "hickory_resolver_probe_duration_seconds";
}
