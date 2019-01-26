// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

use failure::{Backtrace, Context, Fail};
use std::{fmt, io, sync, time::Instant};
use proto::error::{ProtoError, ProtoErrorKind};
use proto::op::Query;

/// An alias for results returned by functions of this crate
pub type ResolveResult<T> = ::std::result::Result<T, ResolveError>;

/// The error kind for errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ResolveErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[fail(display = "{}", _0)]
    Msg(String),

    /// No records were found for a query
    #[fail(display = "no record found for {}", query)]
    NoRecordsFound {
        /// The query for which no records were found.
        query: Query,
        /// A deadline after which the the `NXDOMAIN` response is no longer
        /// valid, and the nameserver should be queried again.
        valid_until: Option<Instant>
    },

    // foreign
    /// An error got returned from IO
    #[fail(display = "io error")]
    Io,

    /// An error got returned by the trust-dns-proto crate
    #[fail(display = "proto error")]
    Proto,

    /// A request timed out
    #[fail(display = "request timed out")]
    Timeout,
}

impl Clone for ResolveErrorKind {
    fn clone(&self) -> Self {
        use self::ResolveErrorKind::*;
        match *self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),
            NoRecordsFound { ref query, valid_until } => NoRecordsFound {
                query: query.clone(),
                valid_until,
            },

            // foreign
            Io => Io,
            Proto => Proto,
            Timeout => Timeout,
        }
    }
}

/// The error type for errors that get returned in the crate
#[derive(Debug)]
pub struct ResolveError {
    inner: Context<ResolveErrorKind>,
}

impl ResolveError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ResolveErrorKind {
        self.inner.get_context()
    }
}

impl Clone for ResolveError {
    fn clone(&self) -> Self {
        ResolveError {
            inner: Context::new(self.inner.get_context().clone()),
        }
    }
}

impl Fail for ResolveError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<ResolveErrorKind> for ResolveError {
    fn from(kind: ResolveErrorKind) -> ResolveError {
        ResolveError {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ResolveErrorKind>> for ResolveError {
    fn from(inner: Context<ResolveErrorKind>) -> ResolveError {
        ResolveError { inner }
    }
}

impl From<&'static str> for ResolveError {
    fn from(msg: &'static str) -> ResolveError {
        ResolveErrorKind::Message(msg).into()
    }
}

#[cfg(target_os = "windows")]
impl From<::ipconfig::error::Error> for ResolveError {
    fn from(e: ::ipconfig::error::Error) -> ResolveError {
        e.context(ResolveErrorKind::Message("failed to read from registry"))
            .into()
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
            io::ErrorKind::TimedOut => e.context(ResolveErrorKind::Timeout).into(),
            _ => e.context(ResolveErrorKind::Io).into(),
        }
    }
}

impl From<ProtoError> for ResolveError {
    fn from(e: ProtoError) -> ResolveError {
        match *e.kind() {
            ProtoErrorKind::Timeout => e.context(ResolveErrorKind::Timeout).into(),
            _ => e.context(ResolveErrorKind::Proto).into(),
        }
    }
}

impl From<ResolveError> for io::Error {
    fn from(e: ResolveError) -> Self {
        match *e.kind() {
            ResolveErrorKind::Timeout => io::Error::new(io::ErrorKind::TimedOut, e.compat()),
            _ => io::Error::new(io::ErrorKind::Other, e.compat()),
        }
    }
}

impl<T> From<sync::PoisonError<T>> for ResolveError {
    fn from(e: sync::PoisonError<T>) -> Self {
        ResolveErrorKind::Msg(format!("lock was poisoned, this is non-recoverable: {}", e)).into()
    }
}
