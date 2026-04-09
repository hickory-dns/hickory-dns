//! Tracing subscriber Layer for DNSTAP event capture.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::client::{DnstapConnection, DnstapMessageType, create_background_sender};
use crate::dnstap_message::{self, DnstapEventParams};
use crate::{DnsTransport, DnstapConfig};

const DNSTAP_TARGET: &str = "hickory_server::dnstap";

/// A [`tracing_subscriber::Layer`] that captures DNS request/response events
/// and sends them as DNSTAP protobuf messages over Frame Streams.
pub struct DnstapLayer {
    sender: mpsc::Sender<Vec<u8>>,
    identity: Arc<Option<Vec<u8>>>,
    version: Arc<Option<Vec<u8>>>,
    log_auth_query: bool,
    log_auth_response: bool,
    log_client_query: bool,
    log_client_response: bool,
    log_resolver_query: bool,
    log_resolver_response: bool,
}

impl DnstapLayer {
    /// Create a new DNSTAP layer and its associated connection handle.
    ///
    /// The layer is immediately usable as a [`tracing_subscriber::Layer`] —
    /// events will be queued in an internal channel.  The returned
    /// [`DnstapConnection`] must be [`start`](DnstapConnection::start)ed
    /// inside a Tokio runtime to actually connect to the collector and drain
    /// the queue.  This two-phase design lets the caller control *when* the
    /// background task (and its "handshake completed" log line) fires relative
    /// to other startup messages.
    pub fn new(config: DnstapConfig) -> (Self, DnstapConnection) {
        let (sender, connection) = create_background_sender(
            config.endpoint.clone(),
            config.buffer_size,
            config.max_backoff,
        );

        let layer = Self {
            sender,
            identity: Arc::new(config.identity),
            version: Arc::new(config.version),
            log_auth_query: config.log_auth_query,
            log_auth_response: config.log_auth_response,
            log_client_query: config.log_client_query,
            log_client_response: config.log_client_response,
            log_resolver_query: config.log_resolver_query,
            log_resolver_response: config.log_resolver_response,
        };

        (layer, connection)
    }

    fn enabled_query_types(&self) -> impl Iterator<Item = DnstapMessageType> + '_ {
        [
            (self.log_auth_query, DnstapMessageType::Auth),
            (self.log_client_query, DnstapMessageType::Client),
            (self.log_resolver_query, DnstapMessageType::Resolver),
        ]
        .into_iter()
        .filter_map(|(enabled, mt)| enabled.then_some(mt))
    }

    fn enabled_response_types(&self) -> impl Iterator<Item = DnstapMessageType> + '_ {
        [
            (self.log_auth_response, DnstapMessageType::Auth),
            (self.log_client_response, DnstapMessageType::Client),
            (self.log_resolver_response, DnstapMessageType::Resolver),
        ]
        .into_iter()
        .filter_map(|(enabled, mt)| enabled.then_some(mt))
    }

    fn send(&self, encoded: Vec<u8>) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.sender.try_send(encoded) {
            tracing::warn!("dnstap channel full, dropping message");
        }
    }
}

/// Per-span data stored in span extensions.
struct DnstapSpanData {
    src_addr: Option<SocketAddr>,
    server_addr: Option<SocketAddr>,
    transport: DnsTransport,
    query_bytes: Option<Vec<u8>>,
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
        "UDP" => DnsTransport::Udp,
        "TCP" => DnsTransport::Tcp,
        "TLS" => DnsTransport::Tls,
        "HTTPS" | "H3" => DnsTransport::Https,
        "QUIC" => DnsTransport::Quic,
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

        // Find the current span to get request context
        let Some(span) = ctx.event_span(event) else {
            return;
        };

        let mut extensions = span.extensions_mut();
        let Some(data) = extensions.get_mut::<DnstapSpanData>() else {
            return;
        };

        let Some(src_addr) = data.src_addr else {
            return;
        };

        match kind {
            "query" => {
                if let Some(ref bytes) = visitor.message_bytes {
                    // Store query bytes for later response event
                    data.query_bytes = Some(bytes.clone());

                    for message_type in self.enabled_query_types() {
                        let encoded = dnstap_message::build_query(&DnstapEventParams {
                            identity: &self.identity,
                            version: &self.version,
                            src_addr,
                            server_addr: data.server_addr,
                            transport: data.transport,
                            query_bytes: bytes,
                            message_type: &message_type,
                        });
                        self.send(encoded);
                    }
                }
            }
            "response" => {
                if let Some(ref response_bytes) = visitor.message_bytes {
                    let query_bytes = data.query_bytes.clone().unwrap_or_default();

                    for message_type in self.enabled_response_types() {
                        let encoded = dnstap_message::build_response(
                            &DnstapEventParams {
                                identity: &self.identity,
                                version: &self.version,
                                src_addr,
                                server_addr: data.server_addr,
                                transport: data.transport,
                                query_bytes: &query_bytes,
                                message_type: &message_type,
                            },
                            response_bytes,
                        );
                        self.send(encoded);
                    }
                }
            }
            _ => {}
        }
    }
}
