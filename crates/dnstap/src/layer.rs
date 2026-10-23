//! Tracing subscriber Layer for DNSTAP event capture.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Metadata, Subscriber};
use tracing_core::Interest;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::client::{
    DnstapConnection, DnstapEvent, DnstapMessageType, MessageTypeFilter, create_background_sender,
};
use crate::dnstap_message::now_time;
#[cfg(feature = "metrics")]
use crate::metrics::DnstapMetrics;
use crate::{DnsTransport, DnstapConfig};

const DNSTAP_TARGET: &str = "hickory_server::dnstap";

/// A [`tracing_subscriber::Layer`] that captures DNS request/response events
/// and sends them as DNSTAP protobuf messages over Frame Streams.
///
/// The layer is intentionally thin: it captures the raw wire bytes and
/// metadata from each tracing event and enqueues a lightweight `DnstapEvent`
/// on the channel.  All protobuf encoding and framing is done by the
/// background sender task, keeping the DNS hot path free of serialization work.
///
/// Message classification is done at the emit site and recorded on the
/// `dns.request` span; resolver hop events carry their fields on the event
/// instead, since they run outside any span.
pub struct DnstapLayer {
    sender: mpsc::Sender<DnstapEvent>,
    filter: MessageTypeFilter,
    drop_count: Arc<AtomicU64>,
    #[cfg(feature = "metrics")]
    metrics: DnstapMetrics,
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
        let filter = MessageTypeFilter::from_config(&config);
        let (sender, connection) = create_background_sender(
            config.endpoint,
            config.buffer_size,
            config.max_backoff,
            Arc::new(config.identity),
            Arc::new(config.version),
        );
        let drop_count = connection.drop_count();
        #[cfg(feature = "metrics")]
        let metrics = connection.metrics();

        (
            Self {
                sender,
                filter,
                drop_count,
                #[cfg(feature = "metrics")]
                metrics,
            },
            connection,
        )
    }

    fn send(&self, event: DnstapEvent) {
        let message_type = event.message_type();
        let query = matches!(event, DnstapEvent::Query { .. });
        if !self.filter.allows(message_type, query) {
            return;
        }
        if self.sender.try_send(event).is_err() {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "metrics")]
            self.metrics.increment_dropped(message_type, query);
        }
    }
}

/// Per-span data stored in span extensions.
struct DnstapSpanData {
    src_addr: Option<SocketAddr>,
    server_addr: Option<SocketAddr>,
    transport: Option<DnsTransport>,
    message_type: Option<DnstapMessageType>,
    /// Answering zone in wire format, recorded on the span by the catalog so
    /// the response frame can carry the bailiwick.
    query_zone: Option<Vec<u8>>,
    query_time: Option<(u64, u32)>,
}

/// Visitor for extracting fields from span attributes.
///
/// Socket addresses arrive as byte fields plus separate u64 ports so span
/// recording never formats or re-parses `SocketAddr` strings. String fields
/// are parsed to their enums on record; a field whose value never parses
/// leaves the slot empty.
#[derive(Default)]
struct SpanVisitor {
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    server_ip: Option<IpAddr>,
    server_port: Option<u16>,
    transport: Option<DnsTransport>,
    message_type: Option<DnstapMessageType>,
}

impl Visit for SpanVisitor {
    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        // Emit sites record 4 or 16 octets; an empty slice means the address
        // is absent and leaves the slot empty.
        let ip = if let Ok(octets) = <[u8; 4]>::try_from(value) {
            IpAddr::V4(Ipv4Addr::from(octets))
        } else if let Ok(octets) = <[u8; 16]>::try_from(value) {
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            return;
        };
        match field.name() {
            "src_addr_bytes" => self.src_ip = Some(ip),
            "server_addr_bytes" => self.server_ip = Some(ip),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "src_port" => self.src_port = Some(value as u16),
            "server_port" => self.server_port = Some(value as u16),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "protocol" => self.transport = parse_transport(value),
            "class" => self.message_type = parse_class(value),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // Display fields land here; the Debug payload still has to be
        // materialized to be parsed. 16 bytes cover every value the emit
        // sites record ("update", "https", ...); anything longer cannot be
        // a valid protocol or class.
        let mut buf = [0u8; 16];
        let Some(s) = write_debug(value, &mut buf) else {
            return;
        };
        self.record_str(field, s);
    }
}

/// Render a `record_debug` payload into `buf` for parsing.
///
/// `None` if the payload did not fit; values that long were never valid
/// field content.
fn write_debug<'a>(value: &dyn fmt::Debug, buf: &'a mut [u8]) -> Option<&'a str> {
    use fmt::Write as _;

    struct SliceWriter<'a> {
        buf: &'a mut [u8],
        len: usize,
        overflow: bool,
    }

    impl fmt::Write for SliceWriter<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let Some(rest) = self.buf.get_mut(self.len..) else {
                self.overflow = true;
                return Err(fmt::Error);
            };
            if s.len() > rest.len() {
                self.overflow = true;
                return Err(fmt::Error);
            }
            rest[..s.len()].copy_from_slice(s.as_bytes());
            self.len += s.len();
            Ok(())
        }
    }

    let mut writer = SliceWriter {
        buf,
        len: 0,
        overflow: false,
    };
    writer.write_fmt(format_args!("{value:?}")).ok()?;
    if writer.overflow {
        return None;
    }
    // record_debug payloads carry no interior NULs, and the written range is
    // fmt output.
    let SliceWriter { buf, len, .. } = writer;
    std::str::from_utf8(&buf[..len]).ok()
}

/// The emit site classifies; spans without a valid class produce no events.
fn parse_class(s: &str) -> Option<DnstapMessageType> {
    match s {
        "auth" => Some(DnstapMessageType::Auth),
        "client" => Some(DnstapMessageType::Client),
        "resolver" => Some(DnstapMessageType::Resolver),
        "update" => Some(DnstapMessageType::Update),
        _ => None,
    }
}

/// Visitor for extracting fields from events.
#[derive(Default)]
struct EventVisitor {
    kind: Option<EventKind>,
    message_bytes: Option<Vec<u8>>,
    query_zone: Option<Vec<u8>>,
    /// Query send time carried by resolver hop responses.
    query_time_sec: Option<u64>,
    query_time_nsec: Option<u64>,
}

/// The `kind` field of a DNSTAP emit event.
///
/// Parsing at record time keeps the hot path free of String traffic; an
/// unknown kind produces no event, matching the previous match-and-skip.
#[derive(Clone, Copy, Debug, PartialEq)]
enum EventKind {
    Query,
    Response,
    Zone,
    ResolverQuery,
    ResolverResponse,
}

impl EventKind {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "query" => Some(Self::Query),
            "response" => Some(Self::Response),
            "zone" => Some(Self::Zone),
            "resolver_query" => Some(Self::ResolverQuery),
            "resolver_response" => Some(Self::ResolverResponse),
            _ => None,
        }
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "kind" {
            self.kind = EventKind::parse(value);
        }
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        match field.name() {
            "message_bytes" => self.message_bytes = Some(value.to_vec()),
            "query_zone" => self.query_zone = Some(value.to_vec()),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "query_time_sec" => self.query_time_sec = Some(value),
            "query_time_nsec" => self.query_time_nsec = Some(value),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // kind might come through as debug if passed without explicit str formatting
        if field.name() == "kind" {
            let mut buf = [0u8; 16];
            let Some(s) = write_debug(value, &mut buf) else {
                return;
            };
            self.kind = EventKind::parse(s);
        }
    }
}

/// Map a protocol string from the span to a transport.
///
/// Returns `None` for unrecognized protocols so that events with unknown
/// transports are skipped rather than mislabeled.
fn parse_transport(s: &str) -> Option<DnsTransport> {
    match s {
        "udp" => Some(DnsTransport::Udp),
        "tcp" => Some(DnsTransport::Tcp),
        "tls" => Some(DnsTransport::Tls),
        "https" | "h3" => Some(DnsTransport::Https),
        "quic" => Some(DnsTransport::Quic),
        _ => None,
    }
}

/// Build an event for a resolver hop from the event fields alone.
///
/// Hop events run outside the request span; endpoints are unknown, so the
/// socket fields stay empty. Hop responses carry the query's send time.
fn resolver_event(
    kind: EventKind,
    bytes: Vec<u8>,
    zone: Vec<u8>,
    query_time: Option<(u64, u32)>,
) -> Option<DnstapEvent> {
    match kind {
        EventKind::ResolverQuery => Some(DnstapEvent::Query {
            message_type: DnstapMessageType::Resolver,
            src_addr: None,
            server_addr: None,
            transport: None,
            query_bytes: bytes,
            query_zone: Some(zone),
            query_time: now_time(),
        }),
        EventKind::ResolverResponse => Some(DnstapEvent::Response {
            message_type: DnstapMessageType::Resolver,
            src_addr: None,
            server_addr: None,
            transport: None,
            query_time: query_time.unwrap_or_else(now_time),
            response_time: now_time(),
            query_zone: Some(zone),
            response_bytes: bytes,
        }),
        _ => None,
    }
}

impl<S> Layer<S> for DnstapLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    // Interest::never() for other targets would block other layers from
    // seeing those events.
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        metadata.target() == DNSTAP_TARGET
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != DNSTAP_TARGET {
            return;
        }

        let mut visitor = SpanVisitor::default();
        attrs.record(&mut visitor);

        let src_addr = visitor
            .src_ip
            .zip(visitor.src_port)
            .map(|(ip, port)| SocketAddr::new(ip, port));
        // An empty server address byte field keeps the slot absent.
        let server_addr = visitor
            .server_ip
            .zip(visitor.server_port)
            .map(|(ip, port)| SocketAddr::new(ip, port));
        let transport = visitor.transport;
        let message_type = visitor.message_type;

        let data = DnstapSpanData {
            src_addr,
            server_addr,
            transport,
            message_type,
            query_zone: None,
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

        let Some(kind) = visitor.kind else {
            return;
        };

        // Resolver hop events carry everything on the event; they run outside
        // the request span.
        match kind {
            EventKind::ResolverQuery | EventKind::ResolverResponse => {
                if let Some(bytes) = visitor.message_bytes {
                    if let Some(zone) = visitor.query_zone {
                        let query_time = visitor
                            .query_time_sec
                            .zip(visitor.query_time_nsec)
                            .map(|(sec, nsec)| (sec, nsec as u32));
                        if let Some(event) = resolver_event(kind, bytes, zone, query_time) {
                            self.send(event);
                        }
                    }
                }
                return;
            }
            _ => {}
        }

        let Some(span) = ctx.event_span(event) else {
            return;
        };

        match kind {
            // The catalog records the answering zone; keep it on the span.
            EventKind::Zone => {
                let Some(zone) = visitor.query_zone else {
                    return;
                };
                let mut ext = span.extensions_mut();
                if let Some(data) = ext.get_mut::<DnstapSpanData>() {
                    data.query_zone = Some(zone);
                }
            }
            EventKind::Query => {
                let Some(bytes) = visitor.message_bytes else {
                    return;
                };
                // Hold the extensions lock only long enough to mutate span data
                // and copy out the metadata needed to build the event.
                let (src_addr, server_addr, transport, message_type, qt) = {
                    let mut ext = span.extensions_mut();
                    let Some(data) = ext.get_mut::<DnstapSpanData>() else {
                        return;
                    };
                    let Some(src_addr) = data.src_addr else {
                        return;
                    };
                    let Some(transport) = data.transport else {
                        return;
                    };
                    let Some(message_type) = data.message_type else {
                        return;
                    };
                    let qt = now_time();
                    data.query_time = Some(qt);
                    (src_addr, data.server_addr, transport, message_type, qt)
                };
                self.send(DnstapEvent::Query {
                    message_type,
                    src_addr: Some(src_addr),
                    server_addr,
                    transport: Some(transport),
                    query_bytes: bytes,
                    query_zone: None,
                    query_time: qt,
                });
            }
            EventKind::Response => {
                let Some(response_bytes) = visitor.message_bytes else {
                    return;
                };
                let (src_addr, server_addr, transport, message_type, query_time, query_zone) = {
                    let mut ext = span.extensions_mut();
                    let Some(data) = ext.get_mut::<DnstapSpanData>() else {
                        return;
                    };
                    let Some(src_addr) = data.src_addr else {
                        return;
                    };
                    let Some(transport) = data.transport else {
                        return;
                    };
                    let Some(message_type) = data.message_type else {
                        return;
                    };
                    let query_time = data.query_time.unwrap_or_else(now_time);
                    let query_zone = data.query_zone.take();
                    (
                        src_addr,
                        data.server_addr,
                        transport,
                        message_type,
                        query_time,
                        query_zone,
                    )
                };
                self.send(DnstapEvent::Response {
                    message_type,
                    src_addr: Some(src_addr),
                    server_addr,
                    transport: Some(transport),
                    query_time,
                    response_time: now_time(),
                    query_zone,
                    response_bytes,
                });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn test_response_without_zone_has_no_bailiwick() {
        let (sender, mut receiver) = mpsc::channel(16);
        let layer = layer_with_sender(sender);

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let span = request_span();
        let _enter = span.enter();

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "query",
            message_bytes = b"\x12\x34\x01\x00".as_slice(),
        );
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
        );
        drop(_enter);

        let query = receiver.try_recv().expect("query event");
        assert!(matches!(
            query,
            DnstapEvent::Query {
                query_zone: None,
                ..
            }
        ));

        let response = receiver.try_recv().expect("response event");
        assert!(matches!(
            response,
            DnstapEvent::Response {
                query_zone: None,
                ..
            }
        ));
        drop(_guard);
    }

    /// A span whose protocol is not UDP must not fall back to the UDP
    /// default; this is the regression test for the mislabeled-transport
    /// bug found in review, where every non-UDP frame recorded as UDP.
    #[test]
    fn test_non_udp_protocol_parse() {
        for (protocol, expected) in [
            ("tcp", DnsTransport::Tcp),
            ("tls", DnsTransport::Tls),
            ("https", DnsTransport::Https),
            ("quic", DnsTransport::Quic),
        ] {
            let (sender, mut receiver) = mpsc::channel(16);
            let layer = layer_with_sender(sender);

            let _guard =
                tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
            let span = tracing::span!(
                target: DNSTAP_TARGET,
                tracing::Level::TRACE,
                "dns.request",
                src_addr_bytes = &Ipv4Addr::new(192, 0, 2, 1).octets()[..],
                src_port = 53u64,
                protocol = %protocol,
                server_addr_bytes = &[][..],
                server_port = 0u64,
                class = %"auth",
            );
            let _enter = span.enter();

            tracing::event!(
                target: DNSTAP_TARGET,
                tracing::Level::TRACE,
                kind = "query",
                message_bytes = b"\x12\x34\x01\x00".as_slice(),
            );
            drop(_enter);

            match receiver.try_recv().expect("query event") {
                DnstapEvent::Query { transport, .. } => {
                    assert_eq!(transport, Some(expected), "protocol {protocol}");
                }
                _ => panic!("expected a query event"),
            }
            drop(_guard);
        }
    }

    #[test]
    fn test_response_carries_answering_zone() {
        let (sender, mut receiver) = mpsc::channel(16);
        let layer = layer_with_sender(sender);

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let span = request_span();
        let _enter = span.enter();

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "zone",
            query_zone = ZONE_WIRE,
        );
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
        );
        drop(_enter);

        let response = receiver.try_recv().expect("response event");
        match response {
            DnstapEvent::Response { query_zone, .. } => {
                assert_eq!(query_zone.as_deref(), Some(ZONE_WIRE));
            }
            _ => panic!("expected a response event"),
        }
        drop(_guard);
    }

    #[test]
    fn test_span_fields_parse_to_enums() {
        let (sender, mut receiver) = mpsc::channel(16);
        let layer = layer_with_sender(sender);

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let span = request_span();
        let _enter = span.enter();

        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "query",
            message_bytes = b"\x12\x34\x01\x00".as_slice(),
        );
        drop(_enter);

        match receiver.try_recv().expect("query event") {
            DnstapEvent::Query {
                message_type,
                transport,
                src_addr,
                server_addr,
                ..
            } => {
                assert_eq!(transport, Some(DnsTransport::Udp));
                assert_eq!(message_type, DnstapMessageType::Auth);
                assert_eq!(
                    src_addr,
                    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53))
                );
                assert_eq!(server_addr, None);
            }
            _ => panic!("expected a query event"),
        }
        drop(_guard);
    }

    #[test]
    fn test_resolver_response_carries_query_time() {
        let (sender, mut receiver) = mpsc::channel(16);
        let layer = DnstapLayer {
            sender,
            filter: MessageTypeFilter::from_config(&DnstapConfig {
                log_resolver_response: true,
                ..Default::default()
            }),
            drop_count: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "metrics")]
            metrics: DnstapMetrics::default(),
        };

        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));

        // Hop responses run outside the request span and carry the query's
        // send time from the emit site.
        tracing::event!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            kind = "resolver_response",
            message_bytes = b"\x12\x34\x81\x80".as_slice(),
            query_zone = ZONE_WIRE,
            query_time_sec = 1_000_000u64,
            query_time_nsec = 123u64,
        );

        match receiver.try_recv().expect("resolver response event") {
            DnstapEvent::Response { query_time, .. } => {
                assert_eq!(query_time, (1_000_000, 123));
            }
            _ => panic!("expected a response event"),
        }
        drop(_guard);
    }

    /// Build a layer that enqueues into the given channel without a
    /// background task, so the tests can inspect the events directly.
    fn layer_with_sender(sender: mpsc::Sender<DnstapEvent>) -> DnstapLayer {
        DnstapLayer {
            sender,
            filter: MessageTypeFilter::from_config(&DnstapConfig {
                log_auth_query: true,
                log_auth_response: true,
                ..Default::default()
            }),
            drop_count: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "metrics")]
            metrics: DnstapMetrics::default(),
        }
    }

    /// An auth-classified request span with the full socket context.
    fn request_span() -> tracing::Span {
        tracing::span!(
            target: DNSTAP_TARGET,
            tracing::Level::TRACE,
            "dns.request",
            src_addr_bytes = &Ipv4Addr::new(192, 0, 2, 1).octets()[..],
            src_port = 53u64,
            protocol = %"udp",
            server_addr_bytes = &[][..],
            server_port = 0u64,
            class = %"auth",
        )
    }

    const ZONE_WIRE: &[u8] = b"\x07example\x03com\x00";
}
