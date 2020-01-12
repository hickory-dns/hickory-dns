// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

use std::{fmt, io, sync, time::Instant};

use thiserror::Error;

use crate::proto::error::{ProtoError, ProtoErrorKind};
use crate::proto::op::Query;
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
        /// A deadline after which the `NXDOMAIN` response is no longer
        /// valid, and the nameserver should be queried again.
        valid_until: Option<Instant>,
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
                valid_until,
            } => NoRecordsFound {
                query: query.clone(),
                valid_until: *valid_until,
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
    kind: ResolveErrorKind,
    backtrack: Option<ExtBacktrace>,
}

impl ResolveError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ResolveErrorKind {
        &self.kind
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref backtrace) = self.backtrack {
            fmt::Display::fmt(&self.kind, f)?;
            fmt::Debug::fmt(backtrace, f)
        } else {
            fmt::Display::fmt(&self.kind, f)
        }
    }
}

impl From<ResolveErrorKind> for ResolveError {
    fn from(kind: ResolveErrorKind) -> ResolveError {
        ResolveError {
            kind,
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
