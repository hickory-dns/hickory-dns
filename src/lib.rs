use core::fmt;

pub use crate::nsd::NsdContainer;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

const CHMOD_RW_EVERYONE: &str = "666";

mod container;
mod nsd;

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
