//! A test framework for all things DNS

use std::env;

use lazy_static::lazy_static;

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
pub mod nsec3;
pub mod record;
mod resolver;
mod trust_anchor;
pub mod tshark;
pub mod zone_file;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

// TODO maybe this should be a TLS variable that each unit test (thread) can override
const DEFAULT_TTL: u32 = 24 * 60 * 60; // 1 day

lazy_static! {
    pub static ref SUBJECT: Implementation = parse_subject();
    pub static ref PEER: Implementation = parse_peer();
}

fn parse_subject() -> Implementation {
    if let Ok(subject) = env::var("DNS_TEST_SUBJECT") {
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

fn parse_peer() -> Implementation {
    if let Ok(peer) = env::var("DNS_TEST_PEER") {
        match peer.as_str() {
            "unbound" => Implementation::Unbound,
            "bind" => Implementation::Bind,
            _ => panic!("`{peer}` is not supported as a test peer implementation"),
        }
    } else {
        Implementation::default()
    }
}

fn repo_root() -> String {
    use std::path::PathBuf;

    let mut repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // /conformance/packages/dns-test
    repo_root.pop(); // /conformance/packages/
    repo_root.pop(); // /conformance
    repo_root.pop(); // /
    repo_root.display().to_string()
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    impl PartialEq for Implementation {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Hickory(_), Self::Hickory(_)) => true,
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    #[test]
    fn immutable_subject() {
        let before = super::SUBJECT.clone();
        let newval = if before == Implementation::Unbound {
            "bind"
        } else {
            "unbound"
        };
        env::set_var("DNS_TEST_SUBJECT", newval);

        let after = super::SUBJECT.clone();
        assert_eq!(before, after);
    }

    #[test]
    fn immutable_peer() {
        let before = super::PEER.clone();
        let newval = if before == Implementation::Unbound {
            "bind"
        } else {
            "unbound"
        };
        env::set_var("DNS_TEST_PEER", newval);

        let after = super::PEER.clone();
        assert_eq!(before, after);
    }
}
