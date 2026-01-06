// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Metrics related to resolver and recursive resolver operations

use hickory_net::xfer::Protocol;
use metrics::{Counter, Unit, counter, describe_counter};

#[derive(Clone, Default)]
pub(crate) struct ResolverMetrics {
    outgoing_queries: ProtocolMetrics,
}

impl ResolverMetrics {
    pub(crate) fn increment_outgoing_query(&self, proto: &Protocol) {
        self.outgoing_queries.increment(proto);
    }
}

#[derive(Clone)]
struct ProtocolMetrics {
    udp: Counter,
    tcp: Counter,
    #[cfg(feature = "__tls")]
    tls: Counter,
    #[cfg(feature = "__https")]
    https: Counter,
    #[cfg(feature = "__quic")]
    quic: Counter,
    #[cfg(feature = "__h3")]
    h3: Counter,
}

impl ProtocolMetrics {
    fn increment(&self, proto: &Protocol) {
        match proto {
            Protocol::Udp => self.udp.increment(1),
            Protocol::Tcp => self.tcp.increment(1),
            #[cfg(feature = "__tls")]
            Protocol::Tls => self.tls.increment(1),
            #[cfg(feature = "__https")]
            Protocol::Https => self.https.increment(1),
            #[cfg(feature = "__quic")]
            Protocol::Quic => self.quic.increment(1),
            #[cfg(feature = "__h3")]
            Protocol::H3 => self.h3.increment(1),
            _ => {}
        }
    }
}

impl Default for ProtocolMetrics {
    fn default() -> Self {
        describe_counter!(
            OUTGOING_QUERIES_TOTAL,
            Unit::Count,
            "Number of outgoing resolver queries by transport protocol"
        );

        let key = "protocol";
        Self {
            udp: counter!(OUTGOING_QUERIES_TOTAL, key => "udp"),
            tcp: counter!(OUTGOING_QUERIES_TOTAL, key => "tcp"),
            #[cfg(feature = "__tls")]
            tls: counter!(OUTGOING_QUERIES_TOTAL, key => "tls"),
            #[cfg(feature = "__https")]
            https: counter!(OUTGOING_QUERIES_TOTAL, key => "https"),
            #[cfg(feature = "__quic")]
            quic: counter!(OUTGOING_QUERIES_TOTAL, key => "quic"),
            #[cfg(feature = "__h3")]
            h3: counter!(OUTGOING_QUERIES_TOTAL, key => "http3"),
        }
    }
}

/// Number of outgoing resolver queries by transport protocol.
pub const OUTGOING_QUERIES_TOTAL: &str = "hickory_resolver_outgoing_queries_total";

/// Metrics for the optional recursive resolver feature
#[cfg(feature = "recursor")]
pub mod recursor {
    #[cfg(feature = "__dnssec")]
    use hickory_proto::{dnssec::Proof, op::Message};
    use metrics::{
        Counter, Gauge, Histogram, Unit, counter, describe_counter, describe_gauge,
        describe_histogram, gauge, histogram,
    };

    #[derive(Clone)]
    pub(crate) struct RecursorMetrics {
        pub(crate) cache_hit_counter: Counter,
        pub(crate) cache_miss_counter: Counter,
        pub(crate) outgoing_query_counter: Counter,
        pub(crate) cache_hit_duration: Histogram,
        pub(crate) cache_miss_duration: Histogram,
        pub(crate) cache_size: Gauge,
        #[cfg(feature = "__dnssec")]
        pub(crate) validated_cache_size: Gauge,
        #[cfg(feature = "__dnssec")]
        pub(crate) dnssec_metrics: DnssecRecursorMetrics,
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
            let cache_hit_duration = histogram!(CACHE_HIT_DURATION);
            describe_histogram!(
                CACHE_HIT_DURATION,
                Unit::Milliseconds,
                "Duration of recursive resolution for queries that are answered from cache."
            );
            let cache_miss_duration = histogram!(CACHE_MISS_DURATION);
            describe_histogram!(
                CACHE_MISS_DURATION,
                Unit::Seconds,
                "Duration of recursive resolution for queries that are not answered from cache."
            );
            let cache_size = gauge!(RESPONSE_CACHE_SIZE);
            describe_gauge!(
                RESPONSE_CACHE_SIZE,
                Unit::Count,
                "Number of entries in the response cache."
            );
            #[cfg(feature = "__dnssec")]
            let validated_cache_size = gauge!(VALIDATED_RESPONSE_CACHE_SIZE);
            #[cfg(feature = "__dnssec")]
            describe_gauge!(
                VALIDATED_RESPONSE_CACHE_SIZE,
                Unit::Count,
                "Number of entries in the DNSSEC validated response cache."
            );
            Self {
                cache_hit_counter,
                cache_miss_counter,
                outgoing_query_counter,
                cache_hit_duration,
                cache_miss_duration,
                cache_size,
                #[cfg(feature = "__dnssec")]
                validated_cache_size,
                #[cfg(feature = "__dnssec")]
                dnssec_metrics: DnssecRecursorMetrics::default(),
            }
        }
    }

    #[cfg(feature = "__dnssec")]
    #[derive(Clone)]
    pub(crate) struct DnssecRecursorMetrics {
        pub(crate) secure_answers_counter: Counter,
        pub(crate) insecure_answers_counter: Counter,
        pub(crate) bogus_answers_counter: Counter,
        pub(crate) indeterminate_answers_counter: Counter,
    }

    #[cfg(feature = "__dnssec")]
    impl DnssecRecursorMetrics {
        pub(crate) fn increment_proof_counter(&self, response: &Message) {
            match response
                .answers()
                .iter()
                .map(|record| record.proof())
                .min()
                .unwrap_or(Proof::Indeterminate)
            {
                Proof::Secure => self.secure_answers_counter.increment(1),
                Proof::Insecure => self.insecure_answers_counter.increment(1),
                Proof::Bogus => self.bogus_answers_counter.increment(1),
                Proof::Indeterminate => self.indeterminate_answers_counter.increment(1),
            }
        }
    }

    #[cfg(feature = "__dnssec")]
    impl Default for DnssecRecursorMetrics {
        fn default() -> Self {
            let secure_answers_counter = counter!(SECURE_ANSWERS_TOTAL);
            describe_counter!(
                SECURE_ANSWERS_TOTAL,
                Unit::Count,
                "Number of recursive requests with answers that were DNSSEC validated as secure"
            );

            let insecure_answers_counter = counter!(INSECURE_ANSWERS_TOTAL);
            describe_counter!(
                INSECURE_ANSWERS_TOTAL,
                Unit::Count,
                "Number of recursive requests with answers that were DNSSEC validated as insecure"
            );

            let bogus_answers_counter = counter!(BOGUS_ANSWERS_TOTAL);
            describe_counter!(
                BOGUS_ANSWERS_TOTAL,
                Unit::Count,
                "Number of recursive requests with answers that were DNSSEC validated as bogus"
            );

            let indeterminate_answers_counter = counter!(INDETERMINATE_ANSWERS_TOTAL);
            describe_counter!(
                INDETERMINATE_ANSWERS_TOTAL,
                Unit::Count,
                "Number of recursive requests with answers that were DNSSEC validated as indeterminate"
            );

            Self {
                secure_answers_counter,
                insecure_answers_counter,
                bogus_answers_counter,
                indeterminate_answers_counter,
            }
        }
    }

    /// Number of recursive requests answered from the cache.
    pub const CACHE_HIT_TOTAL: &str = "hickory_recursor_cache_hit_total";

    /// Number of recursive requests that could not be answered from the cache.
    pub const CACHE_MISS_TOTAL: &str = "hickory_recursor_cache_miss_total";

    /// Number of outgoing queries made during resolution.
    pub const OUTGOING_QUERIES_TOTAL: &str = "hickory_recursor_outgoing_queries_total";

    /// Duration of recursive resolution for queries that are answered from cache.
    pub const CACHE_HIT_DURATION: &str = "hickory_recursor_cache_hit_duration_milliseconds";

    /// Duration of recursive resolution for queries that are not answered from cache.
    pub const CACHE_MISS_DURATION: &str = "hickory_recursor_cache_miss_duration_seconds";

    /// Number of entries in the response cache.
    pub const RESPONSE_CACHE_SIZE: &str = "hickory_recursor_response_cache_size";

    /// Number of entries in the DNSSEC validated response cache.
    #[cfg(feature = "__dnssec")]
    pub const VALIDATED_RESPONSE_CACHE_SIZE: &str =
        "hickory_recursor_validated_response_cache_size";

    /// Number of recursive requests with answers that were DNSSEC validated as secure.
    #[cfg(feature = "__dnssec")]
    pub const SECURE_ANSWERS_TOTAL: &str = "hickory_recursor_dnssec_secure_answers_total";

    /// Number of recursive requests with answers that were DNSSEC validated as insecure.
    #[cfg(feature = "__dnssec")]
    pub const INSECURE_ANSWERS_TOTAL: &str = "hickory_recursor_dnssec_insecure_answers_total";

    /// Number of recursive requests with answers that were DNSSEC validated as bogus.
    #[cfg(feature = "__dnssec")]
    pub const BOGUS_ANSWERS_TOTAL: &str = "hickory_recursor_dnssec_bogus_answers_total";

    /// Number of recursive requests with answers that were DNSSEC validated as indeterminate.
    #[cfg(feature = "__dnssec")]
    pub const INDETERMINATE_ANSWERS_TOTAL: &str =
        "hickory_recursor_dnssec_indeterminate_answers_total";
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
