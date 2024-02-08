//! A test framework for all things DNS

pub use crate::fqdn::FQDN;
pub use crate::recursive_resolver::RecursiveResolver;
pub use crate::trust_anchor::TrustAnchor;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

pub mod client;
mod container;
mod fqdn;
pub mod name_server;
pub mod record;
mod recursive_resolver;
mod trust_anchor;
pub mod zone_file;
