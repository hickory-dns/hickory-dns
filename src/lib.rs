pub use crate::fqdn::FQDN;
pub use crate::recursive_resolver::RecursiveResolver;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

pub mod client;
mod container;
mod fqdn;
pub mod name_server;
pub mod record;
mod recursive_resolver;
pub mod zone_file;
