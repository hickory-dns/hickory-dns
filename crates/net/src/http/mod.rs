// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP protocol related components for DNS over HTTP/2 (DoH) and HTTP/3 (DoH3)

use http::{HeaderMap, HeaderValue};

pub(crate) const MIME_APPLICATION_DNS: &str = "application/dns-message";

/// The default query path for DNS-over-HTTPS if none was given.
pub const DEFAULT_DNS_QUERY_PATH: &str = "/dns-query";

pub(crate) mod error;
pub mod request;
pub mod response;

/// Represents a version of the HTTP spec.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    /// HTTP/2 for DoH.
    #[cfg(feature = "__https")]
    Http2,
    /// HTTP/3 for DoH3.
    #[cfg(feature = "__h3")]
    Http3,
}

impl Version {
    fn to_http(self) -> http::Version {
        match self {
            #[cfg(feature = "__https")]
            Self::Http2 => http::Version::HTTP_2,
            #[cfg(feature = "__h3")]
            Self::Http3 => http::Version::HTTP_3,
        }
    }
}

/// Helper trait to update HTTP headers on requests
///
/// For instance a DoH server may require authentication based
/// on per-request HTTP headers and this trait allows their addition.
pub trait SetHeaders: Send + Sync + 'static {
    /// Get a set of headers to add to the query
    fn set_headers(&self, headers: &mut HeaderMap<HeaderValue>) -> Result<(), error::Error>;
}
