// Copyright 2015-2016 Benjamin Fry
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use rusqlite;

use failure::{Backtrace, Context, Fail};
use std::fmt;

use proto::error::*;

/// An alias for results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for errors that get returned in the crate
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// An error that occurred when recovering from journal
    #[fail(display = "error recovering from journal: {}", _0)]
    Recovery(&'static str),

    /// The number of inserted records didn't match the expected amount
    #[fail(display = "wrong insert count: {} expect: {}", got, expect)]
    WrongInsertCount {
        /// The number of inserted records
        got: usize,
        /// The number of records expected to be inserted
        expect: usize,
    },

    // foreign
    /// An error got returned by the trust-dns-proto crate
    #[fail(display = "proto error")]
    Proto,

    /// An error got returned from the rusqlite crate
    #[fail(display = "sqlite error")]
    Sqlite,

    /// A request timed out
    #[fail(display = "request timed out")]
    Timeout,
}

/// The error type for errors that get returned in the crate
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    /// Get the kind of the error
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Error {
        match *e.kind() {
            ProtoErrorKind::Timeout => e.context(ErrorKind::Timeout).into(),
            _ => e.context(ErrorKind::Proto).into(),
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Error {
        e.context(ErrorKind::Sqlite).into()
    }
}
