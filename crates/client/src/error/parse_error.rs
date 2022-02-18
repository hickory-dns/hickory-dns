// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
// Copyright (C) 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Parse error types for the crate

use std::{fmt, io};

use thiserror::Error;

use super::LexerError;
use crate::proto::{
    error::{ProtoError, ProtoErrorKind},
    rr::RecordType,
};
#[cfg(feature = "backtrace")]
use crate::proto::{trace, ExtBacktrace};
use crate::serialize::txt::Token;

/// An alias for parse results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for parse errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An invalid numerical character was found
    #[error("invalid numerical character: {0}")]
    CharToInt(char),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// A token is missing
    #[error("token is missing: {0}")]
    MissingToken(String),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// A time string could not be parsed
    #[error("invalid time string: {0}")]
    ParseTime(String),

    /// Found an unexpected token in a stream
    #[error("unrecognized token in stream: {0:?}")]
    UnexpectedToken(Token),

    // foreign
    /// An address parse error
    #[error("network address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// A data encoding error
    #[error("data encoding error: {0}")]
    DataEncoding(#[from] data_encoding::DecodeError),

    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error from the lexer
    #[error("lexer error: {0}")]
    Lexer(#[from] LexerError),

    /// A number parsing error
    #[error("error parsing number: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    /// An error got returned by the trust-dns-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// Unknown RecordType
    #[error("unknown RecordType: {0}")]
    UnknownRecordType(u16),

    /// Unknown RecordType
    #[error("unsupported RecordType: {0}")]
    UnsupportedRecordType(RecordType),

    /// A request timed out
    #[error("request timed out")]
    Timeout,
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match self {
            CharToInt(c) => CharToInt(*c),
            Message(msg) => Message(msg),
            MissingToken(ref s) => MissingToken(s.clone()),
            Msg(ref msg) => Msg(msg.clone()),
            ParseTime(ref s) => ParseTime(s.clone()),
            UnexpectedToken(ref token) => UnexpectedToken(token.clone()),

            AddrParse(e) => AddrParse(e.clone()),
            DataEncoding(e) => DataEncoding(*e),
            Io(e) => Io(std::io::Error::from(e.kind())),
            Lexer(e) => Lexer(e.clone()),
            ParseInt(e) => ParseInt(e.clone()),
            Proto(e) => Proto(e.clone()),
            UnsupportedRecordType(ty) => UnsupportedRecordType(*ty),
            UnknownRecordType(ty) => UnknownRecordType(*ty),
            Timeout => Timeout,
        }
    }
}

/// The error type for parse errors that get returned in the crate
#[derive(Error, Debug)]
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

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        ErrorKind::from(e).into()
    }
}

impl From<::data_encoding::DecodeError> for Error {
    fn from(e: data_encoding::DecodeError) -> Self {
        ErrorKind::from(e).into()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => ErrorKind::Timeout.into(),
            _ => ErrorKind::from(e).into(),
        }
    }
}

impl From<LexerError> for Error {
    fn from(e: LexerError) -> Self {
        ErrorKind::from(e).into()
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        ErrorKind::from(e).into()
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Self {
        match *e.kind() {
            ProtoErrorKind::Timeout => ErrorKind::Timeout.into(),
            _ => ErrorKind::from(e).into(),
        }
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_e: std::convert::Infallible) -> Self {
        panic!("infallible")
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match *e.kind() {
            ErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::new(io::ErrorKind::Other, e),
        }
    }
}
