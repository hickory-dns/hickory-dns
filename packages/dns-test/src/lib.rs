//! A test framework for all things DNS

pub use crate::container::Network;
pub use crate::fqdn::FQDN;
pub use crate::implementation::{Implementation, Repository};
pub use crate::resolver::Resolver;
pub use crate::trust_anchor::TrustAnchor;

pub mod client;
mod container;
mod fqdn;
mod implementation;
pub mod name_server;
pub mod record;
mod resolver;
mod trust_anchor;
pub mod tshark;
pub mod zone_file;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

// TODO maybe this should be a TLS variable that each unit test (thread) can override
const DEFAULT_TTL: u32 = 24 * 60 * 60; // 1 day

pub fn subject() -> Implementation {
    if let Ok(subject) = std::env::var("DNS_TEST_SUBJECT") {
        if subject == "unbound" {
            return Implementation::Unbound;
        }

        if subject == "bind" {
            return Implementation::Bind;
        }

        if subject.starts_with("hickory") {
            if let Some(url) = subject.strip_prefix("hickory ") {
                Implementation::Hickory(Repository(url.to_string()))
            } else {
                panic!("the syntax of DNS_TEST_SUBJECT is 'hickory $URL', e.g. 'hickory /tmp/hickory' or 'hickory https://github.com/owner/repo'")
            }
        } else {
            panic!("unknown implementation: {subject}")
        }
    } else {
        Implementation::default()
    }
}

pub fn peer() -> Implementation {
    if let Ok(subject) = std::env::var("DNS_TEST_PEER") {
        match subject.as_str() {
            "unbound" => Implementation::Unbound,
            "bind" => Implementation::Bind,
            _ => panic!("`{subject}` is not supported as a test peer implementation"),
        }
    } else {
        Implementation::default()
    }
}
