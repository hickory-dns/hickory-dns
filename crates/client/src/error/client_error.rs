/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Error types for the crate

use std::{fmt, io};

use failure::{Backtrace, Context, Fail};
use futures::sync::mpsc::SendError;
use proto::error::{ProtoError, ProtoErrorKind};

use error::{DnsSecError, DnsSecErrorKind};

/// An alias for results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[fail(display = "{}", _0)]
    Msg(String),

    // foreign
    /// A dnssec error
    #[fail(display = "dnssec error")]
    DnsSec,

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

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match *self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),
            // foreign
            DnsSec => DnsSec,
            Io => Io,
            Proto => Proto,
            Timeout => Timeout,
        }
    }
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

impl Clone for Error {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match *self.kind() {
            Message(msg) => Message(msg).into(),
            Msg(ref msg) => Msg(msg.clone()).into(),
            //foreign
            DnsSec => DnsSec.into(),
            Io => Io.into(),
            Proto => Proto.into(),
            Timeout => Timeout.into(),
        }
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

impl<T: Send + Sync + 'static> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Self {
        e.context(ErrorKind::Message("error sending to mpsc"))
            .into()
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        ErrorKind::Msg(msg).into()
    }
}

impl From<DnsSecError> for Error {
    fn from(e: DnsSecError) -> Error {
        match *e.kind() {
            DnsSecErrorKind::Timeout => e.context(ErrorKind::Timeout).into(),
            _ => e.context(ErrorKind::DnsSec).into(),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => e.context(ErrorKind::Timeout).into(),
            _ => e.context(ErrorKind::Io).into(),
        }
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

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match *e.kind() {
            ErrorKind::Timeout => io::Error::new(io::ErrorKind::TimedOut, e.compat()),
            _ => io::Error::new(io::ErrorKind::Other, e.compat()),
        }
    }
}

#[test]
fn test_conversion() {
    let io_error = io::Error::new(io::ErrorKind::TimedOut, "mock timeout");

    let error = Error::from(io_error);

    match *error.kind() {
        ErrorKind::Timeout => (),
        _ => panic!("incorrect type: {}", error),
    }
}
