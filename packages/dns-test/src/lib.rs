//! A test framework for all things DNS

use core::fmt;
use std::sync::Once;

pub use crate::container::Network;
pub use crate::fqdn::FQDN;
pub use crate::resolver::Resolver;
pub use crate::trust_anchor::TrustAnchor;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

pub mod client;
mod container;
mod fqdn;
pub mod name_server;
pub mod record;
mod resolver;
mod trust_anchor;
pub mod zone_file;

#[derive(Clone, Copy)]
pub enum Implementation {
    Unbound,
    Hickory,
}

impl Implementation {
    fn dockerfile(&self) -> &'static str {
        match self {
            Implementation::Unbound => include_str!("docker/unbound.Dockerfile"),
            Implementation::Hickory => include_str!("docker/hickory.Dockerfile"),
        }
    }

    fn once(&self) -> &'static Once {
        match self {
            Implementation::Unbound => {
                static UNBOUND_ONCE: Once = Once::new();
                &UNBOUND_ONCE
            }
            Implementation::Hickory => {
                static HICKORY_ONCE: Once = Once::new();
                &HICKORY_ONCE
            }
        }
    }
}

impl Default for Implementation {
    fn default() -> Self {
        Self::Unbound
    }
}

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Implementation::Unbound => "unbound",
            Implementation::Hickory => "hickory",
        };
        f.write_str(s)
    }
}

pub fn subject() -> Implementation {
    if let Ok(subject) = std::env::var("DNS_TEST_SUBJECT") {
        match subject.as_str() {
            "hickory" => Implementation::Hickory,
            "unbound" => Implementation::Unbound,
            _ => panic!("unknown implementation: {subject}"),
        }
    } else {
        Implementation::default()
    }
}
