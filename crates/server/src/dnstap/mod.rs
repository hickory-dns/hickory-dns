//! DNSTAP support for structured DNS event logging.
//!
//! [DNSTAP](https://dnstap.info/) is a flexible, structured binary log format for DNS software,
//! commonly used for security monitoring, analytics, and SIEM integration. It uses
//! [Protocol Buffers](https://protobuf.dev/) for message encoding and
//! [Frame Streams](https://farsightsec.github.io/fstrm/) for transport framing.
//!
//! # Enabling
//!
//! DNSTAP support requires the `dnstap` cargo feature:
//!
//! ```toml
//! hickory-server = { version = "...", features = ["dnstap"] }
//! ```
//!
//! # Architecture
//!
//! The implementation uses an async client ([`DnstapClient`]) with a background sender task
//! connected via an mpsc channel. DNS handler code sends log messages through the channel
//! without blocking request processing. The background task manages the Frame Streams
//! connection to the collector, with automatic reconnection and exponential backoff on failure.
//!
//! # Supported transports
//!
//! - **TCP** — connect to a remote DNSTAP collector via TCP
//! - **Unix socket** — connect via Unix domain socket (unix platforms only)
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

mod client;
mod dnstap_message;
mod framestream;

pub use client::{DnstapClient, DnstapConfig, DnstapEndpoint, DnstapMessageType};
