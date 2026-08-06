//! Tracing subscriber Layer for DNSTAP event capture.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::client::{
    DnstapConnection, DnstapEvent, create_background_sender, query_types_from_config,
    response_types_from_config,
};
use crate::dnstap_message::now_time;
use crate::{DnsTransport, DnstapConfig};

const DNSTAP_TARGET: &str = "hickory_server::dnstap";

/// A [`tracing_subscriber::Layer`] that captures DNS request/response events
/// and sends them as DNSTAP protobuf messages over Frame Streams.
///
/// The layer is intentionally thin: it captures the raw wire bytes and
/// metadata from each tracing event and enqueues a lightweight `DnstapEvent`
/// on the channel.  All protobuf encoding and framing is done by the
/// background sender task, keeping the DNS hot path free of serialization work.
pub struct DnstapLayer {
    sender: mpsc::Sender<DnstapEvent>,
    drop_count: Arc<AtomicU64>,
}

impl DnstapLayer {
    /// Create a new DNSTAP layer and its associated connection handle.
    ///
    /// The layer is immediately usable as a [`tracing_subscriber::Layer`] -
    /// events will be queued in an internal channel.  The returned
    /// [`DnstapConnection`] must be [`start`](DnstapConnection::start)ed
    /// inside a Tokio runtime to actually connect to the collector and drain
    /// the queue.  This two-phase design lets the caller control *when* the
    /// background task (and its "handshake completed" log line) fires relative
    /// to other startup messages.
    pub fn new(config: DnstapConfig) -> (Self, DnstapConnection) {
        let query_types = query_types_from_config(&config);
        let response_types = response_types_from_config(&config);
        let identity = Arc::new(config.identity);
        let version = Arc::new(config.version);

        let (sender, connection) = create_background_sender(
            config.endpoint.clone(),
            config.buffer_size,
            config.max_backoff,
            identity,
            version,
            query_types,
            response_types,
        );
        let drop_count = connection.drop_count();

        (Self { sender, drop_count }, connection)
    }

    fn send(&self, event: DnstapEvent) {
        if self.sender.try_send(event).is_err() {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Per-span data stored in span extensions.
struct DnstapSpanData {
    src_addr: Option<SocketAddr>,
    server_addr: Option<SocketAddr>,
    transport: DnsTransport,
    query_bytes: Option<Vec<u8>>,
    query_time: Option<(u64, u32)>,
}

/// Visitor for extracting fields from span attributes.
#[derive(Default)]
struct SpanVisitor {
    src_addr_str: Option<String>,
    protocol_str: Option<String>,
    server_addr_str: Option<String>,
}

impl Visit for SpanVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let s = format!("{value:?}");
        match field.name() {
            "src_addr" => self.src_addr_str = Some(s),
            "protocol" => self.protocol_str = Some(s),
            "server_addr" => self.server_addr_str = Some(s),
            _ => {}
        }
    }
}

/// Visitor for extracting fields from events.
#[derive(Default)]
struct EventVisitor {
    kind: Option<String>,
    message_bytes: Option<Vec<u8>>,
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "kind" {
            self.kind = Some(value.to_owned());
        }
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        if field.name() == "message_bytes" {
            self.message_bytes = Some(value.to_vec());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // kind might come through as debug if passed without explicit str formatting
        if field.name() == "kind" {
            self.kind = Some(format!("{value:?}"));
        }
    }
}

fn parse_transport(s: &str) -> DnsTransport {
    match s {
        "udp" => DnsTransport::Udp,
        "tcp" => DnsTransport::Tcp,
        "tls" => DnsTransport::Tls,
        "https" | "h3" => DnsTransport::Https,
        "quic" => DnsTransport::Quic,
        _ => DnsTransport::Udp,
    }
}

impl<S> Layer<S> for DnstapLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    // NOTE: We intentionally do NOT override `register_callsite` or `enabled`
    // here. Returning `Interest::never()` or `false` from those methods would
    // block the entire subscriber (including other layers like fmt) from
    // receiving non-DNSTAP events. Instead, we filter by target inside
    // `on_new_span` and `on_event`.

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != DNSTAP_TARGET {
            return;
        }

        let mut visitor = SpanVisitor::default();
        attrs.record(&mut visitor);

        let src_addr = visitor.src_addr_str.as_deref().and_then(|s| s.parse().ok());
        let server_addr = visitor
            .server_addr_str
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok());
        let transport = visitor
            .protocol_str
            .as_deref()
            .map(parse_transport)
            .unwrap_or(DnsTransport::Udp);

        let data = DnstapSpanData {
            src_addr,
            server_addr,
            transport,
            query_bytes: None,
            query_time: None,
        };

        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(data);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != DNSTAP_TARGET {
            return;
        }

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let Some(kind @ ("query" | "response")) = visitor.kind.as_deref() else {
            return;
        };

        let Some(span) = ctx.event_span(event) else {
            return;
        };

        match kind {
            "query" => {
                let Some(ref bytes) = visitor.message_bytes else {
                    return;
                };
                // Hold the extensions lock only long enough to mutate span data
                // and copy out the metadata needed to build the event.
                let (src_addr, server_addr, transport, qt) = {
                    let mut ext = span.extensions_mut();
                    let Some(data) = ext.get_mut::<DnstapSpanData>() else {
                        return;
                    };
                    let Some(src_addr) = data.src_addr else {
                        return;
                    };
                    let qt = now_time();
                    data.query_bytes = Some(bytes.clone());
                    data.query_time = Some(qt);
                    (src_addr, data.server_addr, data.transport, qt)
                };
                self.send(DnstapEvent::Query {
                    src_addr,
                    server_addr,
                    transport,
                    query_bytes: bytes.clone(),
                    query_time: qt,
                });
            }
            "response" => {
                let Some(ref response_bytes) = visitor.message_bytes else {
                    return;
                };
                let (src_addr, server_addr, transport, query_bytes, query_time) = {
                    let mut ext = span.extensions_mut();
                    let Some(data) = ext.get_mut::<DnstapSpanData>() else {
                        return;
                    };
                    let Some(src_addr) = data.src_addr else {
                        return;
                    };
                    let query_bytes = data.query_bytes.clone().unwrap_or_default();
                    let query_time = data.query_time.unwrap_or_else(now_time);
                    (
                        src_addr,
                        data.server_addr,
                        data.transport,
                        query_bytes,
                        query_time,
                    )
                };
                self.send(DnstapEvent::Response {
                    src_addr,
                    server_addr,
                    transport,
                    query_bytes,
                    query_time,
                    response_bytes: response_bytes.clone(),
                });
            }
            _ => {}
        }
    }
}
