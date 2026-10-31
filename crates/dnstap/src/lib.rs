//! DNSTAP support for structured DNS event logging.
//!
//! [DNSTAP](https://dnstap.info/) is a flexible, structured binary log format for DNS software,
//! commonly used for security monitoring, analytics, and SIEM integration. It uses
//! [Protocol Buffers](https://protobuf.dev/) for message encoding and
//! [Frame Streams](https://farsightsec.github.io/fstrm/) for transport framing.
//!
//! # Architecture
//!
//! There are two integration points, both built on the same background-sender pattern:
//!
//! - [`DnstapClient`] - direct API for code that builds and sends DNSTAP events itself.
//!   Calling [`DnstapClient::new`] immediately spawns a background task.
//!
//! - [`DnstapLayer`] - a [`tracing_subscriber::Layer`] that captures DNS events from
//!   `tracing` spans carrying the `hickory_server::dnstap` target. [`DnstapLayer::new`] returns the layer
//!   plus a [`DnstapConnection`] handle; call [`DnstapConnection::start`] inside a Tokio
//!   runtime to spawn the background task. The two-phase design lets the caller control
//!   when the background task (and its startup log) fires relative to other server startup.
//!
//! In both cases the DNS hot path only does a non-blocking channel send. All protobuf
//! encoding, Frame Streams framing, and collector I/O happen in the background task, which
//! reconnects with exponential backoff on failure.
//!
//! # Supported transports
//!
//! - **TCP** - connect to a remote DNSTAP collector via TCP
//! - **Unix socket** - connect via Unix domain socket (unix platforms only)
//!
//! # Per-message-type logging
//!
//! Each combination of message category and direction is toggled by its own flag.
//! The ten supported message types are:
//!
//! | Config option              | Description                                    |
//! |----------------------------|------------------------------------------------|
//! | `log_auth_query`           | Authoritative queries received                 |
//! | `log_auth_response`        | Authoritative responses sent                   |
//! | `log_client_query`         | Client queries received                        |
//! | `log_client_response`      | Client responses sent                          |
//! | `log_resolver_query`       | Recursor queries sent upstream                 |
//! | `log_resolver_response`    | Recursor responses received from upstream      |
//! | `log_forwarder_query`      | Forwarded queries sent to an upstream resolver |
//! | `log_forwarder_response`   | Forwarded responses received from an upstream  |
//! | `log_update_query`         | Dynamic update requests received               |
//! | `log_update_response`      | Dynamic update responses sent                  |
//!
//! All default to `false`.
//!
//! Note on upstream traffic: the resolver records every query it sends and
//! every response it receives. Queries that ask the upstream to recurse (RD
//! set) are `FORWARDER_QUERY`/`FORWARDER_RESPONSE` messages, while recursor
//! hops, which clear RD, are `RESOLVER_QUERY`/`RESOLVER_RESPONSE`. Upstream
//! events carry the upstream address as `response_address`/`response_port` and
//! the transport as `socket_protocol`; recursor hops also carry the bailiwick
//! as `query_zone`, while forwarded lookups are recorded without one.
//! Authoritative response frames carry the answering zone as the bailiwick
//! (`query_zone`).
//!
//! # Configuration example
//!
//! ```toml
//! [dnstap]
//! enabled = true
//! tcp_address = "127.0.0.1:6000"
//! send_identity = true
//! # identity = "custom-name"  # defaults to hostname
//! send_version = true
//! # version = "custom-version"  # defaults to package version
//! buffer_size = 4096
//! log_client_query = true
//! log_client_response = true
//! ```
//!
//! # Metrics
//!
//! With the `metrics` feature enabled, the layer and [`DnstapClient`] export
//! the DNSTAP pipeline through the `metrics` crate:
//!
//! - `hickory_dnstap_sent_events_total` and `hickory_dnstap_dropped_events_total`,
//!   labeled by `category` (auth, client, resolver, forwarder, update) and `direction`
//!   (query, response); drops also carry a `reason` of `buffer_full` or
//!   `write_failed`.
//! - `hickory_dnstap_filtered_events_total` for events the `log_*` flags
//!   discarded before buffering.
//! - `hickory_dnstap_sent_bytes_total` for delivered payload bytes, and
//!   `hickory_dnstap_batch_flush_duration_seconds` for how long the writer
//!   blocked on the collector.
//! - `hickory_dnstap_buffer_events` and `hickory_dnstap_buffer_bytes` gauges
//!   against `hickory_dnstap_buffer_max_events_total` and
//!   `hickory_dnstap_buffer_max_bytes_total`, the bounds `buffer_size`
//!   sets. The max counters are written once when the sender starts, so
//!   their `rate()` is always zero. Buffer memory is also bounded by
//!   [`QUEUED_BYTES_PER_EVENT`].
//! - `hickory_dnstap_collector_session_up`, `hickory_dnstap_session_reconnects_total`
//!   and `hickory_dnstap_reconnect_backoff_seconds` for the state of the
//!   collector session.
//!
//! Install the metrics recorder before [`DnstapConnection::start`] or
//! [`DnstapClient::new`]: handles bound before a recorder exists never report.

#![warn(clippy::dbg_macro, clippy::print_stdout, missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod client;
mod dnstap_message;
mod event;
mod framestream;
mod layer;
#[cfg(feature = "metrics")]
pub mod metrics;

pub use client::{
    DnstapClient, DnstapConfig, DnstapConnection, DnstapEndpoint, QUEUED_BYTES_PER_EVENT,
};
pub use event::DnstapMessageType;
pub use layer::DnstapLayer;

/// DNS transport protocol for the DNSTAP `socket_protocol` field.
///
/// This is a simplified protocol enum that decouples the DNSTAP crate from
/// the server's internal `Protocol` type and its feature-gated variants.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DnsTransport {
    /// DNS over UDP (RFC 1035).
    Udp,
    /// DNS over TCP (RFC 1035).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484), including HTTP/3.
    Https,
    /// DNS over QUIC (RFC 9250).
    Quic,
}
