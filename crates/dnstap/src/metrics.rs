// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Metrics related to DNSTAP event logging

use metrics::{Counter, Gauge, Unit, counter, describe_counter, describe_gauge, gauge};

use crate::client::DnstapMessageType;

/// Number of DNSTAP events encoded and written to the collector, by message
/// category and direction.
pub const EVENTS_SENT_TOTAL: &str = "hickory_dnstap_events_sent_total";

/// Number of DNSTAP events not delivered to the collector, by message category
/// and direction. Events are dropped when the internal channel is full, or
/// lost with a failed write.
pub const EVENTS_DROPPED_TOTAL: &str = "hickory_dnstap_events_dropped_total";

/// Messages waiting in the queue when the sender picks up work.
pub const QUEUE_DEPTH: &str = "hickory_dnstap_queue_depth";

/// Message bytes waiting in the queue when the sender picks up work.
pub const QUEUE_BYTES: &str = "hickory_dnstap_queue_bytes";

/// Counters for DNSTAP event delivery, exported through the `metrics` crate.
///
/// Handles are registered once and held for the lifetime of the client or
/// layer, amortizing callsite registration.
#[derive(Clone)]
pub(crate) struct DnstapMetrics {
    sent: [Counter; 8],
    dropped: [Counter; 8],
    queue_depth: Gauge,
    queue_bytes: Gauge,
}

impl DnstapMetrics {
    pub(crate) fn increment_sent(&self, message_type: DnstapMessageType, query: bool) {
        self.sent[index(message_type, query)].increment(1);
    }

    pub(crate) fn increment_dropped(&self, message_type: DnstapMessageType, query: bool) {
        self.dropped[index(message_type, query)].increment(1);
    }

    pub(crate) fn set_queue(&self, events: usize, bytes: usize) {
        self.queue_depth.set(events as f64);
        self.queue_bytes.set(bytes as f64);
    }
}

/// Index into the counter arrays, matching the `Default` label order:
/// categories auth, client, resolver, update, with queries before responses
/// within each.
fn index(message_type: DnstapMessageType, query: bool) -> usize {
    let category = match message_type {
        DnstapMessageType::Auth => 0,
        DnstapMessageType::Client => 1,
        DnstapMessageType::Resolver => 2,
        DnstapMessageType::Update => 3,
    };
    category * 2 + usize::from(!query)
}

impl Default for DnstapMetrics {
    fn default() -> Self {
        describe_counter!(
            EVENTS_SENT_TOTAL,
            Unit::Count,
            "Number of DNSTAP events written to the collector by message type."
        );
        describe_counter!(
            EVENTS_DROPPED_TOTAL,
            Unit::Count,
            "Number of DNSTAP events dropped due to a full internal channel or a failed write, by message type."
        );
        describe_gauge!(
            QUEUE_DEPTH,
            Unit::Count,
            "Number of DNSTAP events waiting in the internal queue."
        );
        describe_gauge!(
            QUEUE_BYTES,
            Unit::Bytes,
            "Payload bytes waiting in the internal queue."
        );

        let categories = ["auth", "client", "resolver", "update"];
        let directions = ["query", "response"];
        let labels = |i: usize| {
            let (category, direction) = (categories[i / 2], directions[i % 2]);
            (category, direction)
        };

        Self {
            sent: std::array::from_fn(|i| {
                let (category, direction) = labels(i);
                counter!(EVENTS_SENT_TOTAL, "category" => category, "direction" => direction)
            }),
            dropped: std::array::from_fn(|i| {
                let (category, direction) = labels(i);
                counter!(EVENTS_DROPPED_TOTAL, "category" => category, "direction" => direction)
            }),
            queue_depth: gauge!(QUEUE_DEPTH),
            queue_bytes: gauge!(QUEUE_BYTES),
        }
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use std::collections::HashMap;

    use metrics::{Key, Label, SharedString, with_local_recorder};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use test_support::{assert_counter_eq, assert_gauge_eq};

    use super::*;

    #[test]
    fn test_counters_increment_by_type_and_direction() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let metrics = DnstapMetrics::default();

            metrics.increment_sent(DnstapMessageType::Auth, true);
            metrics.increment_sent(DnstapMessageType::Auth, true);
            metrics.increment_sent(DnstapMessageType::Auth, false);
            metrics.increment_sent(DnstapMessageType::Update, true);
            metrics.increment_dropped(DnstapMessageType::Client, false);
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        let sent = |category: &'static str, direction: &'static str| {
            (
                EVENTS_SENT_TOTAL,
                vec![
                    Label::new("category", category),
                    Label::new("direction", direction),
                ],
            )
        };
        let dropped = |category: &'static str, direction: &'static str| {
            (
                EVENTS_DROPPED_TOTAL,
                vec![
                    Label::new("category", category),
                    Label::new("direction", direction),
                ],
            )
        };

        let (name, labels) = sent("auth", "query");
        assert_counter_eq(&map, name, labels, 2);
        let (name, labels) = sent("auth", "response");
        assert_counter_eq(&map, name, labels, 1);
        let (name, labels) = sent("update", "query");
        assert_counter_eq(&map, name, labels, 1);

        let (name, labels) = dropped("client", "response");
        assert_counter_eq(&map, name, labels, 1);
        // DebuggingRecorder creates every registered series, so untouched
        // counters appear with value zero.
        let (name, labels) = dropped("auth", "query");
        assert_counter_eq(&map, name, labels, 0);
    }

    #[test]
    fn test_queue_gauges_track_occupancy() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let metrics = DnstapMetrics::default();

            metrics.set_queue(3, 4096);
            #[allow(clippy::mutable_key_type)]
            let map = snapshotter.snapshot().into_hashmap();
            assert_gauge_eq(&map, QUEUE_DEPTH, vec![], 3);
            assert_eq!(queued_bytes(&map), 4096.0);

            metrics.set_queue(0, 0);
            #[allow(clippy::mutable_key_type)]
            let map = snapshotter.snapshot().into_hashmap();
            assert_gauge_eq(&map, QUEUE_DEPTH, vec![], 0);
            assert_eq!(queued_bytes(&map), 0.0);
        });
    }

    /// Reads the byte gauge directly: `assert_gauge_eq` pins `Unit::Count`,
    /// and this gauge reports bytes.
    fn queued_bytes(
        map: &HashMap<CompositeKey, (Option<Unit>, Option<SharedString>, DebugValue)>,
    ) -> f64 {
        match map.get(&CompositeKey::new(
            MetricKind::Gauge,
            Key::from_parts(QUEUE_BYTES, vec![]),
        )) {
            Some((Some(Unit::Bytes), _, DebugValue::Gauge(value))) => value.into_inner(),
            other => panic!("expected a queue bytes gauge in bytes, got {other:?}"),
        }
    }
}
