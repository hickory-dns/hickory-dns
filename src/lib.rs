pub use crate::authoritative_name_server::AuthoritativeNameServer;
pub use crate::domain::Domain;
pub use crate::recursive_resolver::RecursiveResolver;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

const CHMOD_RW_EVERYONE: &str = "666";

mod authoritative_name_server;
pub mod container;
mod domain;
mod recursive_resolver;
