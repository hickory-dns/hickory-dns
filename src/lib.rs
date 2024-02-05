pub use crate::authoritative_name_server::AuthoritativeNameServer;
pub use crate::recursive_resolver::RecursiveResolver;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

const CHMOD_RW_EVERYONE: &str = "666";

mod authoritative_name_server;
mod container;
mod recursive_resolver;

pub enum Domain<'a> {
    Root,
    Tld { domain: &'a str },
}

impl Domain<'_> {
    fn fqdn(&self) -> &str {
        match self {
            Domain::Root => ".",
            Domain::Tld { domain } => domain,
        }
    }
}
