//! DNSTAP support for structured DNS event logging.
//!
//! DNSTAP is a flexible, structured binary log format for DNS software.
//! It uses Protocol Buffers for message encoding and Frame Streams for transport.

mod client;
mod dnstap_message;
mod framestream;

pub use client::{DnstapClient, DnstapConfig, DnstapEndpoint};
