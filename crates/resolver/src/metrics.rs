// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Metrics related to resolver and recursive resolver operations

/// Metrics for the optional recursive resolver feature
#[cfg(feature = "recursor")]
pub(super) mod recursor {
    use metrics::{Counter, Unit, counter, describe_counter};

    #[derive(Clone)]
    pub(crate) struct RecursorMetrics {
        pub(crate) cache_hit_counter: Counter,
        pub(crate) cache_miss_counter: Counter,
        pub(crate) outgoing_query_counter: Counter,
    }

    impl RecursorMetrics {
        pub(crate) fn new() -> Self {
            let cache_hit_counter = counter!("hickory_recursor_cache_hit_total");
            describe_counter!(
                "hickory_recursor_cache_hit_total",
                Unit::Count,
                "Number of recursive requests answered from the cache."
            );
            let cache_miss_counter = counter!("hickory_recursor_cache_miss_total");
            describe_counter!(
                "hickory_recursor_cache_miss_total",
                Unit::Count,
                "Number of recursive requests that could not be answered from the cache."
            );
            let outgoing_query_counter = counter!("hickory_recursor_outgoing_queries_total");
            describe_counter!(
                "hickory_recursor_outgoing_queries_total",
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
}

/// Metrics for the optional resolver opportunistic encryption feature
#[cfg(any(feature = "__tls", feature = "__quic"))]
pub(crate) mod opportunistic_encryption {
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
                "hickory_resolver_probe_attempts_total",
                Unit::Count,
                "Number of opportunistic encrypted name server probe requests attempted."
            );
            let probe_attempts = counter!("hickory_resolver_probe_attempts_total", "protocol" => protocol.to_string());

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
            let probe_timeouts = counter!("hickory_resolver_probe_timeouts_total", "protocol" => protocol.to_string());

            describe_counter!(
                "hickory_resolver_probe_successes_total",
                Unit::Count,
                "Number of opportunistic encrypted name server probe requests that succeeded"
            );
            let probe_successes = counter!("hickory_resolver_probe_successes_total", "protocol" => protocol.to_string());

            describe_histogram!(
                "hickory_resolver_probe_duration_seconds",
                Unit::Seconds,
                "Duration of opportunistic encryption probe request"
            );
            let probe_duration = histogram!("hickory_resolver_probe_duration_seconds", "protocol" => protocol.to_string());

            Self {
                probe_attempts,
                probe_errors,
                probe_timeouts,
                probe_successes,
                probe_duration,
            }
        }
    }
}
