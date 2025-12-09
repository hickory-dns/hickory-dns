// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP protocol related components for DNS over HTTP/2 (DoH) and HTTP/3 (DoH3)

use core::num::ParseIntError;
use std::io;

use alloc::string::String;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, ToStrError};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use thiserror::Error;

use crate::error::ProtoError;

pub mod request;

/// Create a new Response for an http dns-message request
///
/// ```text
/// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
///
///  4.2.1.  Handling DNS and HTTP Errors
///
/// DNS response codes indicate either success or failure for the DNS
/// query.  A successful HTTP response with a 2xx status code (see
/// Section 6.3 of [RFC7231]) is used for any valid DNS response,
/// regardless of the DNS response code.  For example, a successful 2xx
/// HTTP status code is used even with a DNS message whose DNS response
/// code indicates failure, such as SERVFAIL or NXDOMAIN.
///
/// HTTP responses with non-successful HTTP status codes do not contain
/// replies to the original DNS question in the HTTP request.  DoH
/// clients need to use the same semantic processing of non-successful
/// HTTP status codes as other HTTP clients.  This might mean that the
/// DoH client retries the query with the same DoH server, such as if
/// there are authorization failures (HTTP status code 401; see
/// Section 3.1 of [RFC7235]).  It could also mean that the DoH client
/// retries with a different DoH server, such as for unsupported media
/// types (HTTP status code 415; see Section 6.5.13 of [RFC7231]), or
/// where the server cannot generate a representation suitable for the
/// client (HTTP status code 406; see Section 6.5.6 of [RFC7231]), and so
/// on.
/// ```
pub fn response(version: Version, message_len: usize) -> Result<Response<()>, Error> {
    Response::builder()
        .status(StatusCode::OK)
        .version(version.to_http())
        .header(CONTENT_TYPE, crate::http::MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| ProtoError::from(format!("invalid response: {e}")).into())
}

/// Internal HTTP error type
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to decode header value to string
    #[error("header decode error: {0}")]
    Decode(#[from] ToStrError),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Unable to parse header value as number
    #[error("unable to parse number: {0}")]
    ParseInt(#[from] ParseIntError),

    /// A proto error
    #[error("proto error: {0}")]
    ProtoError(#[from] ProtoError),

    /// An HTTP/2 related error
    #[error("H2: {0}")]
    #[cfg(feature = "__https")]
    H2(#[from] h2::Error),

    /// An HTTP/3 related error
    #[error("H3: {0}")]
    #[cfg(feature = "__h3")]
    H3(#[from] h3::error::StreamError),
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg)
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Self::Msg(msg)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        Self::other(format!("https: {err}"))
    }
}

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
    fn set_headers(&self, headers: &mut HeaderMap<HeaderValue>) -> Result<(), Error>;
}

pub(crate) const MIME_APPLICATION_DNS: &str = "application/dns-message";

/// The default query path for DNS-over-HTTPS if none was given.
pub const DEFAULT_DNS_QUERY_PATH: &str = "/dns-query";
