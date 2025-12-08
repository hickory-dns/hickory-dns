#![warn(
    clippy::alloc_instead_of_core,
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::unimplemented,
    clippy::use_self,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(
    clippy::single_component_path_imports,
    clippy::upper_case_acronyms, // can be removed on a major release boundary
    clippy::bool_to_int_with_if,
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use hickory_proto as proto;

pub mod client;

#[cfg(feature = "__dnssec")]
pub mod dnssec;

mod error;
pub use error::{DnsError, ForwardNSData, NetError, NetErrorKind, NoRecords};

#[cfg(feature = "__https")]
pub mod h2;
#[cfg(feature = "__h3")]
pub mod h3;
#[cfg(any(feature = "__https", feature = "__h3"))]
pub mod http;
#[cfg(feature = "mdns")]
pub mod multicast;
#[cfg(all(feature = "__quic", feature = "tokio"))]
pub mod quic;
pub mod runtime;
#[cfg(feature = "__tls")]
pub mod rustls;
pub mod tcp;
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::BufDnsStreamHandle;
#[doc(hidden)]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
