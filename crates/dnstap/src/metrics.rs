// Copyright 2015-2026 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your option. This
// file may not be copied, modified, or distributed except according to those
// terms.

//! Metrics related to DNSTAP event logging

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use metrics::{
    Counter, Gauge, Histogram, Unit, counter, describe_counter, describe_gauge, describe_histogram,
    gauge, histogram,
};

use crate::event::DnstapMessageType;

/// Number of DNSTAP events written to the collector, by message category and
/// direction.
pub const SENT_EVENTS_TOTAL: &str = "hickory_dnstap_sent_events_total";

/// Number of DNSTAP events not delivered to the collector, by message category,
/// direction, and reason. Events are dropped when the internal buffer is full,
/// or lost with a failed write.
pub const DROPPED_EVENTS_TOTAL: &str = "hickory_dnstap_dropped_events_total";

/// Number of DNSTAP events discarded by the configured message type filter.
pub const FILTERED_EVENTS_TOTAL: &str = "hickory_dnstap_filtered_events_total";

/// Payload bytes written to the collector.
pub const SENT_BYTES_TOTAL: &str = "hickory_dnstap_sent_bytes_total";

/// Number of times the sender re-established its session after a failure.
pub const SESSION_RECONNECTS_TOTAL: &str = "hickory_dnstap_session_reconnects_total";

/// Events waiting in the buffer when an event is captured, or once the sender
/// has written a batch.
pub const BUFFER_EVENTS: &str = "hickory_dnstap_buffer_events";

/// Message bytes waiting in the buffer when an event is captured, or once the
/// sender has written a batch.
pub const BUFFER_BYTES: &str = "hickory_dnstap_buffer_bytes";

/// Number of events the buffer holds before it refuses captures.
pub const BUFFER_MAX_EVENTS_TOTAL: &str = "hickory_dnstap_buffer_max_events_total";

/// Payload bytes the buffer holds before it refuses captures.
pub const BUFFER_MAX_BYTES_TOTAL: &str = "hickory_dnstap_buffer_max_bytes_total";

/// Whether a collector session is established (1) or not (0).
pub const COLLECTOR_SESSION_UP: &str = "hickory_dnstap_collector_session_up";

/// Reconnect delay currently in effect.
pub const RECONNECT_BACKOFF_SECONDS: &str = "hickory_dnstap_reconnect_backoff_seconds";

/// Time the sender spent writing one batch to the collector.
pub const BATCH_FLUSH_DURATION_SECONDS: &str = "hickory_dnstap_batch_flush_duration_seconds";

/// Why an event did not reach the collector.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DropReason {
    /// The buffer budget refused it, or the channel had no free slot.
    BufferFull,
    /// Writing the batch to the collector failed.
    WriteFailed,
}

impl DropReason {
    fn index(self) -> usize {
        match self {
            Self::BufferFull => 0,
            Self::WriteFailed => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::BufferFull => "buffer_full",
            Self::WriteFailed => "write_failed",
        }
    }

    fn all() -> impl Iterator<Item = Self> {
        [Self::BufferFull, Self::WriteFailed].into_iter()
    }
}

/// Counters and gauges for DNSTAP event delivery, exported through the
/// `metrics` crate.
#[derive(Clone, Default)]
pub(crate) struct DnstapMetrics {
    // Registered by `init`, once the caller's recorder is installed.
    handles: Arc<OnceLock<Handles>>,
}

struct Handles {
    sent_events: [Counter; SERIES.len()],
    dropped_events: [[Counter; SERIES.len()]; 2],
    filtered_events: [Counter; SERIES.len()],
    sent_bytes: Counter,
    session_reconnects: Counter,
    buffer_events: Gauge,
    buffer_bytes: Gauge,
    buffer_max_events: Counter,
    buffer_max_bytes: Counter,
    collector_session_up: Gauge,
    reconnect_backoff: Gauge,
    batch_flush_duration: Histogram,
}

impl DnstapMetrics {
    /// Register the counters, gauges and histogram with the currently
    /// installed recorder.
    ///
    /// A handle binds to the recorder present at creation and never follows a
    /// recorder installed later, so this runs from
    /// [`DnstapConnection::start`](crate::DnstapConnection::start).
    ///
    /// `max_events` and `max_bytes` are the configured buffer bounds, reported
    /// by the max counters.
    pub(crate) fn init(&self, max_events: usize, max_bytes: usize) {
        let _ = self.handles.set(Handles::new(max_events, max_bytes));
    }

    pub(crate) fn increment_sent_batch(&self, counts: &BatchCounts) {
        if let Some(handles) = self.handles.get() {
            increment(&handles.sent_events, counts);
        }
    }

    pub(crate) fn add_sent_bytes(&self, bytes: usize) {
        if let Some(handles) = self.handles.get() {
            handles.sent_bytes.increment(bytes as u64);
        }
    }

    pub(crate) fn increment_dropped(
        &self,
        message_type: DnstapMessageType,
        query: bool,
        reason: DropReason,
    ) {
        if let Some(handles) = self.handles.get() {
            handles.dropped_events[reason.index()][index(message_type, query)].increment(1);
        }
    }

    pub(crate) fn increment_dropped_batch(&self, counts: &BatchCounts, reason: DropReason) {
        if let Some(handles) = self.handles.get() {
            increment(&handles.dropped_events[reason.index()], counts);
        }
    }

    pub(crate) fn increment_filtered(&self, message_type: DnstapMessageType, query: bool) {
        if let Some(handles) = self.handles.get() {
            handles.filtered_events[index(message_type, query)].increment(1);
        }
    }

    pub(crate) fn increment_session_reconnect(&self) {
        if let Some(handles) = self.handles.get() {
            handles.session_reconnects.increment(1);
        }
    }

    pub(crate) fn set_buffer(&self, events: usize, bytes: usize) {
        if let Some(handles) = self.handles.get() {
            handles.buffer_events.set(events as f64);
            handles.buffer_bytes.set(bytes as f64);
        }
    }

    pub(crate) fn set_collector_session_up(&self, up: bool) {
        if let Some(handles) = self.handles.get() {
            handles.collector_session_up.set(u8::from(up) as f64);
        }
    }

    pub(crate) fn set_reconnect_backoff(&self, backoff: Duration) {
        if let Some(handles) = self.handles.get() {
            handles.reconnect_backoff.set(backoff.as_secs_f64());
        }
    }

    pub(crate) fn observe_batch_flush_duration(&self, elapsed: Duration) {
        if let Some(handles) = self.handles.get() {
            handles.batch_flush_duration.record(elapsed.as_secs_f64());
        }
    }
}

/// One entry per message type and direction, in counter-array order: queries
/// before responses.
const SERIES: [(DnstapMessageType, bool); 10] = [
    (DnstapMessageType::Auth, true),
    (DnstapMessageType::Auth, false),
    (DnstapMessageType::Client, true),
    (DnstapMessageType::Client, false),
    (DnstapMessageType::Resolver, true),
    (DnstapMessageType::Resolver, false),
    (DnstapMessageType::Forwarder, true),
    (DnstapMessageType::Forwarder, false),
    (DnstapMessageType::Update, true),
    (DnstapMessageType::Update, false),
];

/// Category label for a DNSTAP message type.
fn category(message_type: DnstapMessageType) -> &'static str {
    match message_type {
        DnstapMessageType::Auth => "auth",
        DnstapMessageType::Client => "client",
        DnstapMessageType::Resolver => "resolver",
        DnstapMessageType::Forwarder => "forwarder",
        DnstapMessageType::Update => "update",
    }
}

/// Index into the counter arrays, matching the [`SERIES`] order.
fn index(message_type: DnstapMessageType, query: bool) -> usize {
    let i = message_type as usize * 2 + usize::from(!query);
    debug_assert_eq!(SERIES[i], (message_type, query));
    i
}

/// Events of one batch, counted per category and direction.
///
/// A batch is only counted once the collector has taken it, so the sender
/// tallies the batch here instead of holding on to every event.
#[derive(Default)]
pub(crate) struct BatchCounts([u64; SERIES.len()]);

impl BatchCounts {
    pub(crate) fn add(&mut self, message_type: DnstapMessageType, query: bool) {
        self.0[index(message_type, query)] += 1;
    }
}

/// Add a batch's tallies to the counters, skipping the categories it never
/// carried.
fn increment(counters: &[Counter; SERIES.len()], counts: &BatchCounts) {
    for (counter, count) in counters.iter().zip(counts.0) {
        if count > 0 {
            counter.increment(count);
        }
    }
}

impl Handles {
    fn new(max_events: usize, max_bytes: usize) -> Self {
        describe_counter!(
            SENT_EVENTS_TOTAL,
            Unit::Count,
            "Number of DNSTAP events written to the collector, by category and direction."
        );
        describe_counter!(
            DROPPED_EVENTS_TOTAL,
            Unit::Count,
            "Number of DNSTAP events not delivered to the collector, by category, direction and reason."
        );
        describe_counter!(
            FILTERED_EVENTS_TOTAL,
            Unit::Count,
            "Number of DNSTAP events discarded by the message type filter."
        );
        describe_counter!(
            SENT_BYTES_TOTAL,
            Unit::Bytes,
            "Payload bytes written to the collector."
        );
        describe_counter!(
            SESSION_RECONNECTS_TOTAL,
            Unit::Count,
            "Number of times the sender re-established its session after a failure."
        );
        describe_gauge!(
            BUFFER_EVENTS,
            Unit::Count,
            "Number of DNSTAP events waiting in the internal buffer."
        );
        describe_gauge!(
            BUFFER_BYTES,
            Unit::Bytes,
            "Payload bytes waiting in the internal buffer."
        );
        describe_counter!(
            BUFFER_MAX_EVENTS_TOTAL,
            Unit::Count,
            "Configured number of events the internal buffer holds before refusing captures."
        );
        describe_counter!(
            BUFFER_MAX_BYTES_TOTAL,
            Unit::Bytes,
            "Configured payload bytes the internal buffer holds before refusing captures."
        );
        describe_gauge!(
            COLLECTOR_SESSION_UP,
            Unit::Count,
            "Whether a collector session is established (1) or not (0)."
        );
        describe_gauge!(
            RECONNECT_BACKOFF_SECONDS,
            Unit::Seconds,
            "Reconnect delay currently in effect."
        );
        describe_histogram!(
            BATCH_FLUSH_DURATION_SECONDS,
            Unit::Seconds,
            "Time the sender spent writing one batch to the collector."
        );

        let labels = |i: usize| {
            let (message_type, query) = SERIES[i];
            let direction = if query { "query" } else { "response" };
            (category(message_type), direction)
        };

        let handles = Self {
            sent_events: std::array::from_fn(|i| {
                let (category, direction) = labels(i);
                counter!(SENT_EVENTS_TOTAL, "category" => category, "direction" => direction)
            }),
            dropped_events: std::array::from_fn(|reason| {
                let reason = DropReason::all().nth(reason).unwrap().label();
                std::array::from_fn(|i| {
                    let (category, direction) = labels(i);
                    counter!(DROPPED_EVENTS_TOTAL, "category" => category, "direction" => direction, "reason" => reason)
                })
            }),
            filtered_events: std::array::from_fn(|i| {
                let (category, direction) = labels(i);
                counter!(FILTERED_EVENTS_TOTAL, "category" => category, "direction" => direction)
            }),
            sent_bytes: counter!(SENT_BYTES_TOTAL),
            session_reconnects: counter!(SESSION_RECONNECTS_TOTAL),
            buffer_events: gauge!(BUFFER_EVENTS),
            buffer_bytes: gauge!(BUFFER_BYTES),
            buffer_max_events: counter!(BUFFER_MAX_EVENTS_TOTAL),
            buffer_max_bytes: counter!(BUFFER_MAX_BYTES_TOTAL),
            collector_session_up: gauge!(COLLECTOR_SESSION_UP),
            reconnect_backoff: gauge!(RECONNECT_BACKOFF_SECONDS),
            batch_flush_duration: histogram!(BATCH_FLUSH_DURATION_SECONDS),
        };

        // Counters start at zero, but a gauge has no value until it is set, so
        // seed every gauge. The buffer bounds come from configuration, so they
        // are set rather than added to keep a second `init` from doubling them.
        handles.buffer_events.set(0.0);
        handles.buffer_bytes.set(0.0);
        handles.buffer_max_events.absolute(max_events as u64);
        handles.buffer_max_bytes.absolute(max_bytes as u64);
        handles.collector_session_up.set(0.0);
        handles.reconnect_backoff.set(0.0);
        handles
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use std::collections::HashMap;

    use metrics::{Key, Label, SharedString, with_local_recorder};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};
    use test_support::{assert_counter_eq, assert_gauge_eq, assert_histogram_sample_count_eq};

    use super::*;

    #[test]
    fn test_counters_increment_by_type_and_direction() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let metrics = DnstapMetrics::default();
            metrics.init(16, 32 * 1024);

            let mut sent = BatchCounts::default();
            sent.add(DnstapMessageType::Auth, true);
            sent.add(DnstapMessageType::Auth, true);
            sent.add(DnstapMessageType::Auth, false);
            sent.add(DnstapMessageType::Update, true);
            metrics.increment_sent_batch(&sent);
            metrics.increment_dropped(DnstapMessageType::Client, false, DropReason::BufferFull);
            metrics.increment_filtered(DnstapMessageType::Resolver, true);
            metrics.add_sent_bytes(1024);
            metrics.increment_session_reconnect();
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        let labeled = |name: &'static str, category: &'static str, direction: &'static str| {
            (
                name,
                vec![
                    Label::new("category", category),
                    Label::new("direction", direction),
                ],
            )
        };
        let dropped = |category: &'static str, direction: &'static str, reason: &'static str| {
            (
                DROPPED_EVENTS_TOTAL,
                vec![
                    Label::new("category", category),
                    Label::new("direction", direction),
                    Label::new("reason", reason),
                ],
            )
        };

        let (name, labels) = labeled(SENT_EVENTS_TOTAL, "auth", "query");
        assert_counter_eq(&map, name, labels, 2);
        let (name, labels) = labeled(SENT_EVENTS_TOTAL, "auth", "response");
        assert_counter_eq(&map, name, labels, 1);
        let (name, labels) = labeled(SENT_EVENTS_TOTAL, "update", "query");
        assert_counter_eq(&map, name, labels, 1);

        let (name, labels) = dropped("client", "response", "buffer_full");
        assert_counter_eq(&map, name, labels, 1);
        // The same event counted under a different reason must stay distinct.
        let (name, labels) = dropped("client", "response", "write_failed");
        assert_counter_eq(&map, name, labels, 0);

        let (name, labels) = labeled(FILTERED_EVENTS_TOTAL, "resolver", "query");
        assert_counter_eq(&map, name, labels, 1);
        // DebuggingRecorder creates every registered series, so untouched
        // counters appear with value zero.
        let (name, labels) = labeled(FILTERED_EVENTS_TOTAL, "auth", "query");
        assert_counter_eq(&map, name, labels, 0);

        assert_eq!(counter_in_bytes(&map, SENT_BYTES_TOTAL), 1024);
        assert_counter_eq(&map, SESSION_RECONNECTS_TOTAL, vec![], 1);
    }

    #[test]
    fn test_buffer_gauges_track_occupancy() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let metrics = DnstapMetrics::default();
            metrics.init(16, 32 * 1024);

            metrics.set_buffer(3, 4096);
            #[allow(clippy::mutable_key_type)]
            let map = snapshotter.snapshot().into_hashmap();
            assert_gauge_eq(&map, BUFFER_EVENTS, vec![], 3);
            assert_eq!(gauge_in_bytes(&map, BUFFER_BYTES), 4096.0);

            metrics.set_buffer(0, 0);
            #[allow(clippy::mutable_key_type)]
            let map = snapshotter.snapshot().into_hashmap();
            assert_gauge_eq(&map, BUFFER_EVENTS, vec![], 0);
            assert_eq!(gauge_in_bytes(&map, BUFFER_BYTES), 0.0);
        });
    }

    #[test]
    fn test_max_counters_report_the_buffer_bounds() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let metrics = DnstapMetrics::default();
            metrics.init(16, 32 * 1024);
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();
        assert_counter_eq(&map, BUFFER_MAX_EVENTS_TOTAL, vec![], 16);
        assert_eq!(
            counter_in_bytes(&map, BUFFER_MAX_BYTES_TOTAL),
            (32 * 1024) as u64
        );
    }

    #[test]
    fn test_session_and_flush_metrics() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let metrics = DnstapMetrics::default();
            metrics.init(16, 32 * 1024);

            // The sender starts disconnected, with no delay scheduled.
            #[allow(clippy::mutable_key_type)]
            let map = snapshotter.snapshot().into_hashmap();
            assert_gauge_eq(&map, COLLECTOR_SESSION_UP, vec![], 0);
            assert_eq!(gauge_in_seconds(&map, RECONNECT_BACKOFF_SECONDS), 0.0);

            metrics.set_collector_session_up(true);
            metrics.set_reconnect_backoff(Duration::from_millis(400));
            metrics.observe_batch_flush_duration(Duration::from_millis(5));
            metrics.observe_batch_flush_duration(Duration::from_millis(7));

            #[allow(clippy::mutable_key_type)]
            let map = snapshotter.snapshot().into_hashmap();
            assert_gauge_eq(&map, COLLECTOR_SESSION_UP, vec![], 1);
            assert_eq!(gauge_in_seconds(&map, RECONNECT_BACKOFF_SECONDS), 0.4);
            assert_histogram_sample_count_eq(
                &map,
                BATCH_FLUSH_DURATION_SECONDS,
                vec![],
                2,
                Unit::Seconds,
            );
        });
    }

    #[test]
    fn test_handles_register_when_the_sender_starts() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let config = crate::DnstapConfig {
                endpoint: crate::DnstapEndpoint::Tcp("127.0.0.1:9".parse().unwrap()),
                ..Default::default()
            };
            let (_layer, connection) = crate::DnstapLayer::new(config);
            #[allow(clippy::mutable_key_type)]
            let before = snapshotter.snapshot().into_hashmap();
            assert!(
                before.is_empty(),
                "building the layer must not register handles, the recorder may not exist yet"
            );

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async { connection.start() });

            #[allow(clippy::mutable_key_type)]
            let after = snapshotter.snapshot().into_hashmap();
            assert_eq!(
                after.len(),
                4 * SERIES.len() + 9,
                "starting the sender must register the sent, dropped and filtered counters, \
                 the delivery counters, four gauges and the batch flush histogram"
            );
            assert!(
                after.contains_key(&CompositeKey::new(
                    MetricKind::Gauge,
                    Key::from_parts(BUFFER_EVENTS, vec![]),
                )),
                "starting the sender must register the buffer events gauge"
            );
        });
    }

    /// Reads a byte counter directly: `assert_counter_eq` pins `Unit::Count`,
    /// and this counter reports bytes.
    fn counter_in_bytes(
        map: &HashMap<CompositeKey, (Option<Unit>, Option<SharedString>, DebugValue)>,
        name: &'static str,
    ) -> u64 {
        match map.get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_parts(name, vec![]),
        )) {
            Some((Some(Unit::Bytes), _, DebugValue::Counter(value))) => *value,
            other => panic!("expected a bytes counter for {name}, got {other:?}"),
        }
    }

    /// Reads a byte gauge directly: `assert_gauge_eq` pins `Unit::Count`, and
    /// these gauges report bytes.
    fn gauge_in_bytes(
        map: &HashMap<CompositeKey, (Option<Unit>, Option<SharedString>, DebugValue)>,
        name: &'static str,
    ) -> f64 {
        match map.get(&CompositeKey::new(
            MetricKind::Gauge,
            Key::from_parts(name, vec![]),
        )) {
            Some((Some(Unit::Bytes), _, DebugValue::Gauge(value))) => value.into_inner(),
            other => panic!("expected a bytes gauge for {name}, got {other:?}"),
        }
    }

    /// Reads a seconds gauge for the same reason.
    fn gauge_in_seconds(
        map: &HashMap<CompositeKey, (Option<Unit>, Option<SharedString>, DebugValue)>,
        name: &'static str,
    ) -> f64 {
        match map.get(&CompositeKey::new(
            MetricKind::Gauge,
            Key::from_parts(name, vec![]),
        )) {
            Some((Some(Unit::Seconds), _, DebugValue::Gauge(value))) => value.into_inner(),
            other => panic!("expected a seconds gauge for {name}, got {other:?}"),
        }
    }
}
