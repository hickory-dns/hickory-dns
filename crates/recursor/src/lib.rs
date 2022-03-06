//! A recursive DNS resolver based on the Trust-DNS (stub) resolver

#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
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
)]
#![recursion_limit = "2048"]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
mod recursor;

pub use error::{Error, ErrorKind};
pub use recursor::Recursor;
pub use trust_dns_proto as proto;
pub use trust_dns_resolver as resolver;
pub use trust_dns_resolver::config::NameServerConfig;
