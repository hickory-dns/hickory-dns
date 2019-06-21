// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{fmt, io};

use failure::{Backtrace, Context, Fail};
use h2;
use trust_dns_proto::error::ProtoError;
use typed_headers;

/// An alias for results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Fail)]
pub enum ErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[fail(display = "{}", _0)]
    Msg(String),

    #[fail(display = "proto error: {}", _0)]
    ProtoError(ProtoError),

    #[fail(display = "bad header: {}", _0)]
    TypedHeaders(typed_headers::Error),

    #[fail(display = "h2: {}", _0)]
    H2(h2::Error),
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

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Error {
        ErrorKind::Message(msg).into()
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        ErrorKind::Msg(msg).into()
    }
}

impl From<ProtoError> for Error {
    fn from(msg: ProtoError) -> Self {
        ErrorKind::ProtoError(msg).into()
    }
}

impl From<typed_headers::Error> for Error {
    fn from(msg: typed_headers::Error) -> Self {
        ErrorKind::TypedHeaders(msg).into()
    }
}

impl From<h2::Error> for Error {
    fn from(msg: h2::Error) -> Self {
        ErrorKind::H2(msg).into()
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, format!("https: {}", err))
    }
}
