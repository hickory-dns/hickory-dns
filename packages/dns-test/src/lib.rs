//! A test framework for all things DNS

use std::borrow::Cow;
use std::path::Path;

use url::Url;

pub use crate::container::Network;
pub use crate::fqdn::FQDN;
pub use crate::resolver::Resolver;
pub use crate::trust_anchor::TrustAnchor;

pub mod client;
mod container;
mod fqdn;
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

#[derive(Clone)]
pub enum Implementation {
    Bind,
    Hickory(Repository<'static>),
    Unbound,
}

impl Implementation {
    #[must_use]
    pub fn is_bind(&self) -> bool {
        matches!(self, Self::Bind)
    }
}

#[derive(Clone)]
pub struct Repository<'a> {
    inner: Cow<'a, str>,
}

impl Repository<'_> {
    fn as_str(&self) -> &str {
        &self.inner
    }
}

/// checks that `input` looks like a valid repository which can be either local or remote
///
/// # Panics
///
/// this function panics if `input` is not a local `Path` that exists or a well-formed URL
#[allow(non_snake_case)]
pub fn Repository(input: impl Into<Cow<'static, str>>) -> Repository<'static> {
    let input = input.into();
    assert!(
        Path::new(&*input).exists() || Url::parse(&input).is_ok(),
        "{input} is not a valid repository"
    );
    Repository { inner: input }
}

impl Default for Implementation {
    fn default() -> Self {
        Self::Unbound
    }
}

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
