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
//!   `tracing` spans emitted by `hickory-server`. [`DnstapLayer::new`] returns the layer
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
//! Following the Unbound-style model, each combination of message category and direction
//! can be independently enabled or disabled. The six supported message types are:
//!
//! | Config option            | Description                          |
//! |--------------------------|--------------------------------------|
//! | `log_auth_query`         | Authoritative queries received       |
//! | `log_auth_response`      | Authoritative responses sent         |
//! | `log_client_query`       | Client queries received              |
//! | `log_client_response`    | Client responses sent                |
//! | `log_resolver_query`     | Outbound resolver queries            |
//! | `log_resolver_response`  | Inbound resolver responses           |
//!
//! All default to `false`.
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

#![warn(clippy::dbg_macro, clippy::print_stdout, missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod client;
mod dnstap_message;
mod framestream;
mod layer;

pub use client::{DnstapClient, DnstapConfig, DnstapConnection, DnstapEndpoint, DnstapMessageType};
pub use layer::DnstapLayer;

/// DNS transport protocol for the DNSTAP `socket_protocol` field.
///
/// This is a simplified protocol enum that decouples the DNSTAP crate from
/// the server's internal `Protocol` type and its feature-gated variants.
#[derive(Clone, Copy, Debug)]
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
