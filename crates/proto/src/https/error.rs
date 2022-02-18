// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::num::ParseIntError;
use std::{fmt, io};

use crate::error::ProtoError;
use h2;
use http::header::ToStrError;
use thiserror::Error;

#[cfg(feature = "backtrace")]
use crate::{trace, ExtBacktrace};

/// An alias for results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

// TODO: remove this and put in ProtoError
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErrorKind {
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

    #[error("proto error: {0}")]
    ProtoError(#[from] ProtoError),

    #[error("h2: {0}")]
    H2(#[from] h2::Error),
}

/// The error type for errors that get returned in the crate
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl Error {
    /// Get the kind of the error
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
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

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Self {
        ErrorKind::Message(msg).into()
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        ErrorKind::Msg(msg).into()
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        ErrorKind::from(err).into()
    }
}

impl From<ToStrError> for Error {
    fn from(err: ToStrError) -> Self {
        ErrorKind::from(err).into()
    }
}

impl From<ProtoError> for Error {
    fn from(msg: ProtoError) -> Self {
        ErrorKind::ProtoError(msg).into()
    }
}

impl From<h2::Error> for Error {
    fn from(msg: h2::Error) -> Self {
        ErrorKind::H2(msg).into()
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        Self::new(io::ErrorKind::Other, format!("https: {}", err))
    }
}
