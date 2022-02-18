// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lexer error types for the crate

use std::fmt;

use thiserror::Error;

#[cfg(feature = "backtrace")]
use crate::proto::{trace, ExtBacktrace};

/// An alias for lexer results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for lexer errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Error, Clone)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Unexpected end of input
    #[error("unexpected end of input")]
    EOF,

    /// An illegal character was found
    #[error("illegal character input: {0}")]
    IllegalCharacter(char),

    /// An illegal state was reached
    #[error("illegal state: {0}")]
    IllegalState(&'static str),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An unclosed list was found
    #[error("unclosed list, missing ')'")]
    UnclosedList,

    /// An unclosed quoted string was found
    #[error("unclosed quoted string")]
    UnclosedQuotedString,

    /// An unrecognized character was found
    #[error("unrecognized character input: {0}")]
    UnrecognizedChar(char),

    /// An unrecognized dollar content was found
    #[error("unrecognized dollar content: {0}")]
    UnrecognizedDollar(String),

    /// An unrecognized octet was found
    #[error("unrecognized octet: {0:x}")]
    UnrecognizedOctet(u32),
}

/// The error type for lexer errors that get returned in the crate
#[derive(Clone, Error, Debug)]
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

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
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
