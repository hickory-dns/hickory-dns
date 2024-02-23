//! A test framework for all things DNS

use core::fmt;
use std::borrow::Cow;
use std::path::Path;
use std::sync::Once;

use url::Url;

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
pub mod tshark;
pub mod zone_file;

#[derive(Clone)]
pub enum Implementation {
    Unbound,
    Hickory(Repository<'static>),
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

impl Implementation {
    fn dockerfile(&self) -> &'static str {
        match self {
            Implementation::Unbound => include_str!("docker/unbound.Dockerfile"),
            Implementation::Hickory { .. } => include_str!("docker/hickory.Dockerfile"),
        }
    }

    fn once(&self) -> &'static Once {
        match self {
            Implementation::Unbound => {
                static UNBOUND_ONCE: Once = Once::new();
                &UNBOUND_ONCE
            }

            Implementation::Hickory { .. } => {
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
            Implementation::Hickory { .. } => "hickory",
        };
        f.write_str(s)
    }
}

pub fn subject() -> Implementation {
    if let Ok(subject) = std::env::var("DNS_TEST_SUBJECT") {
        if subject == "unbound" {
            return Implementation::Unbound;
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
    Implementation::default()
}
