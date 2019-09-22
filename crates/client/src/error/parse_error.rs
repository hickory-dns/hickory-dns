/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 * Copyright (C) 2017 Google LLC.
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

//! Parse error types for the crate

use std::{fmt, io};

use failure::{Backtrace, Context, Fail};
use proto::error::{ProtoError, ProtoErrorKind};

use super::LexerError;
use crate::serialize::txt::Token;

/// An alias for parse results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for parse errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// An invalid numerical character was found
    #[fail(display = "invalid numerical character: {}", _0)]
    CharToInt(char),

    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// A token is missing
    #[fail(display = "token is missing: {}", _0)]
    MissingToken(String),

    /// An error with an arbitrary message, stored as String
    #[fail(display = "{}", _0)]
    Msg(String),

    /// A time string could not be parsed
    #[fail(display = "invalid time string: {}", _0)]
    ParseTime(String),

    /// Found an unexpected token in a stream
    #[fail(display = "unrecognized token in stream: {:?}", _0)]
    UnexpectedToken(Token),

    // foreign
    /// An address parse error
    #[fail(display = "network address parse error")]
    AddrParse,

    /// A data encoding error
    #[fail(display = "data encoding error")]
    DataEncoding,

    /// An error got returned from IO
    #[fail(display = "io error")]
    Io,

    /// An error from the lexer
    #[fail(display = "lexer error")]
    Lexer,

    /// A number parsing error
    #[fail(display = "error parsing number")]
    ParseInt,

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
            CharToInt(c) => CharToInt(c),
            Message(msg) => Message(msg),
            MissingToken(ref s) => MissingToken(s.clone()),
            Msg(ref msg) => Msg(msg.clone()),
            ParseTime(ref s) => ParseTime(s.clone()),
            UnexpectedToken(ref token) => UnexpectedToken(token.clone()),

            AddrParse => AddrParse,
            DataEncoding => DataEncoding,
            Io => Io,
            Lexer => Lexer,
            ParseInt => ParseInt,
            Proto => Proto,
            Timeout => Timeout,
        }
    }
}

/// The error type for parse errors that get returned in the crate
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

impl From<::std::net::AddrParseError> for Error {
    fn from(e: ::std::net::AddrParseError) -> Error {
        e.context(ErrorKind::AddrParse).into()
    }
}

impl From<::data_encoding::DecodeError> for Error {
    fn from(e: ::data_encoding::DecodeError) -> Error {
        e.context(ErrorKind::DataEncoding).into()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        match e.kind() {
            io::ErrorKind::TimedOut => e.context(ErrorKind::Timeout).into(),
            _ => e.context(ErrorKind::Io).into(),
        }
    }
}

impl From<LexerError> for Error {
    fn from(e: LexerError) -> Error {
        e.context(ErrorKind::Lexer).into()
    }
}

impl From<::std::num::ParseIntError> for Error {
    fn from(e: ::std::num::ParseIntError) -> Error {
        e.context(ErrorKind::ParseInt).into()
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
