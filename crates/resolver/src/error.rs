// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

use std::cmp::Ordering;
use std::{fmt, io, sync};

use thiserror::Error;

use crate::proto::error::{ProtoError, ProtoErrorKind};
use crate::proto::op::{Query, ResponseCode};
use crate::proto::rr::rdata::SOA;
use crate::proto::xfer::retry_dns_handle::RetryableError;
use crate::proto::xfer::DnsResponse;
#[cfg(feature = "with-backtrace")]
use crate::proto::{trace, ExtBacktrace};

/// An alias for results returned by functions of this crate
pub type ResolveResult<T> = ::std::result::Result<T, ResolveError>;

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
pub enum ResolveErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// No records were found for a query
    #[error("no record found for {query}")]
    NoRecordsFound {
        /// The query for which no records were found.
        query: Query,
        /// If an SOA is present, then this is an authoritative response.
        soa: Option<SOA>,
        /// negative ttl, as determined from DnsResponse::negative_ttl
        ///  this will only be present if the SOA was also present.
        negative_ttl: Option<u32>,
        /// ResponseCode, if `NXDOMAIN`, the domain does not exist (and no other types).
        ///   If `NoError`, then the domain exists but there exist either other types at the same label, or subzones of that label.
        response_code: ResponseCode,
        /// If we trust `NXDOMAIN` errors from this server
        trusted: bool,
    },

    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error got returned by the trust-dns-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// A request timed out
    #[error("request timed out")]
    Timeout,
}

impl Clone for ResolveErrorKind {
    fn clone(&self) -> Self {
        use self::ResolveErrorKind::*;
        match self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),
            NoRecordsFound {
                ref query,
                ref soa,
                negative_ttl,
                response_code,
                trusted,
            } => NoRecordsFound {
                query: query.clone(),
                soa: soa.clone(),
                negative_ttl: *negative_ttl,
                response_code: *response_code,
                trusted: *trusted,
            },
            // foreign
            Io(io) => ResolveErrorKind::from(std::io::Error::from(io.kind())),
            Proto(proto) => ResolveErrorKind::from(proto.clone()),
            Timeout => Timeout,
        }
    }
}

/// The error type for errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct ResolveError {
    pub(crate) kind: ResolveErrorKind,
    #[cfg(feature = "with-backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl ResolveError {
    pub(crate) fn nx_error(
        query: Query,
        soa: Option<SOA>,
        negative_ttl: Option<u32>,
        response_code: ResponseCode,
        trusted: bool,
    ) -> ResolveError {
        ResolveErrorKind::NoRecordsFound {
            query,
            soa,
            negative_ttl,
            response_code,
            trusted,
        }
        .into()
    }

    /// Get the kind of the error
    pub fn kind(&self) -> &ResolveErrorKind {
        &self.kind
    }

    /// A conversion to determine if the response is an error
    pub fn from_response(response: DnsResponse, trust_nx: bool) -> Result<DnsResponse, Self> {
        match response.response_code() {
            ResponseCode::ServFail => {
                let note = "Nameserver responded with SERVFAIL";
                debug!("{}", note);

                let mut response = response;
                let soa = response.soa();
                let query = response.take_queries().drain(..).next().unwrap_or_default();
                let error_kind = ResolveErrorKind::NoRecordsFound {
                    query,
                    soa,
                    negative_ttl: None,
                    response_code: ResponseCode::ServFail,
                    trusted: false,
                };

                Err(ResolveError::from(error_kind))
            }
            // Some NXDOMAIN responses contain CNAME referals, that will not be an error
            ResponseCode::NXDomain if !response.contains_answer() => {
                let note = "Nameserver responded with NXDomain";
                debug!("{}", note);

                // TODO: if authoritative, this is cacheable, store a TTL (currently that requires time, need a "now" here)
                // let valid_until = if response.is_authoritative() { now + response.get_negative_ttl() };

                let mut response = response;
                let soa = response.soa();
                let negative_ttl = response.negative_ttl();

                let query = response.take_queries().drain(..).next().unwrap_or_default();
                let error_kind = ResolveErrorKind::NoRecordsFound {
                    query,
                    soa,
                    negative_ttl,
                    response_code: ResponseCode::NXDomain,
                    trusted: trust_nx,
                };

                Err(ResolveError::from(error_kind))
            }
            // No answers are available, CNAME referals are not failures
            ResponseCode::NoError if !response.contains_answer() => {
                let note = "Nameserver responded with NoError and no records";
                debug!("{}", note);

                // TODO: if authoritative, this is cacheable, store a TTL (currently that requires time, need a "now" here)
                // let valid_until = if response.is_authoritative() { now + response.get_negative_ttl() };

                let mut response = response;
                let soa = response.soa();
                let negative_ttl = response.negative_ttl();

                let query = response.take_queries().drain(..).next().unwrap_or_default();
                let error_kind = ResolveErrorKind::NoRecordsFound {
                    query,
                    soa,
                    negative_ttl,
                    response_code: ResponseCode::NoError,
                    trusted: false,
                };

                Err(ResolveError::from(error_kind))
            }
            _ => Ok(response),
        }
    }

    /// Compare two errors to see if one contains a server response.
    pub(crate) fn cmp_specificity(&self, other: &Self) -> Ordering {
        let kind = self.kind();
        let other = other.kind();

        match (kind, other) {
            (ResolveErrorKind::NoRecordsFound { .. }, ResolveErrorKind::NoRecordsFound { .. }) => {
                return Ordering::Equal
            }
            (ResolveErrorKind::NoRecordsFound { .. }, _) => return Ordering::Greater,
            (_, ResolveErrorKind::NoRecordsFound { .. }) => return Ordering::Less,
            _ => (),
        }

        match (kind, other) {
            (ResolveErrorKind::Io { .. }, ResolveErrorKind::Io { .. }) => return Ordering::Equal,
            (ResolveErrorKind::Io { .. }, _) => return Ordering::Greater,
            (_, ResolveErrorKind::Io { .. }) => return Ordering::Less,
            _ => (),
        }

        match (kind, other) {
            (ResolveErrorKind::Proto { .. }, ResolveErrorKind::Proto { .. }) => {
                return Ordering::Equal
            }
            (ResolveErrorKind::Proto { .. }, _) => return Ordering::Greater,
            (_, ResolveErrorKind::Proto { .. }) => return Ordering::Less,
            _ => (),
        }

        match (kind, other) {
            (ResolveErrorKind::Timeout, ResolveErrorKind::Timeout) => return Ordering::Equal,
            (ResolveErrorKind::Timeout, _) => return Ordering::Greater,
            (_, ResolveErrorKind::Timeout) => return Ordering::Less,
            _ => (),
        }

        Ordering::Equal
    }
}

impl RetryableError for ResolveError {
    fn should_retry(&self) -> bool {
        !matches!(self.kind(), ResolveErrorKind::NoRecordsFound { trusted, .. } if *trusted)
    }

    fn attempted(&self) -> bool {
        match self.kind() {
            ResolveErrorKind::Proto(e) => !matches!(e.kind(), ProtoErrorKind::Busy),
            _ => true,
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "with-backtrace")] {
                if let Some(ref backtrace) = self.backtrack {
                    fmt::Display::fmt(&self.kind, f)?;
                    fmt::Debug::fmt(backtrace, f)
                } else {
                    fmt::Display::fmt(&self.kind, f)
                }
            } else {
                fmt::Display::fmt(&self.kind, f)
            }
        }
    }
}

impl From<ResolveErrorKind> for ResolveError {
    fn from(kind: ResolveErrorKind) -> ResolveError {
        ResolveError {
            kind,
            #[cfg(feature = "with-backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for ResolveError {
    fn from(msg: &'static str) -> ResolveError {
        ResolveErrorKind::Message(msg).into()
    }
}

#[cfg(target_os = "windows")]
impl From<ipconfig::error::Error> for ResolveError {
    fn from(e: ipconfig::error::Error) -> ResolveError {
        ResolveErrorKind::Msg(format!("failed to read from registry: {}", e)).into()
    }
}

impl From<String> for ResolveError {
    fn from(msg: String) -> ResolveError {
        ResolveErrorKind::Msg(msg).into()
    }
}

impl From<io::Error> for ResolveError {
    fn from(e: io::Error) -> ResolveError {
        match e.kind() {
            io::ErrorKind::TimedOut => ResolveErrorKind::Timeout.into(),
            _ => ResolveErrorKind::from(e).into(),
        }
    }
}

impl From<ProtoError> for ResolveError {
    fn from(e: ProtoError) -> ResolveError {
        match *e.kind() {
            ProtoErrorKind::Timeout => ResolveErrorKind::Timeout.into(),
            _ => ResolveErrorKind::from(e).into(),
        }
    }
}

impl From<ResolveError> for io::Error {
    fn from(e: ResolveError) -> Self {
        match e.kind() {
            ResolveErrorKind::Timeout => io::Error::new(io::ErrorKind::TimedOut, e),
            _ => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

impl<T> From<sync::PoisonError<T>> for ResolveError {
    fn from(e: sync::PoisonError<T>) -> Self {
        ResolveErrorKind::Msg(format!("lock was poisoned, this is non-recoverable: {}", e)).into()
    }
}
