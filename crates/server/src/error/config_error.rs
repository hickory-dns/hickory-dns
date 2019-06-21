// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use failure::{Backtrace, Context, Fail};
use std::{fmt, io};

/// An alias for results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for errors that get returned in the crate
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    // foreign
    /// An error got returned from IO
    #[fail(display = "io error")]
    Io,

    /// An error occurred while decoding toml data
    #[fail(display = "toml decode error")]
    TomlDecode,
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

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        e.context(ErrorKind::Io).into()
    }
}

impl From<::toml::de::Error> for Error {
    fn from(e: ::toml::de::Error) -> Error {
        e.context(ErrorKind::TomlDecode).into()
    }
}
