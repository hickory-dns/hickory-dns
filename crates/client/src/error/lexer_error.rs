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

//! Lexer error types for the crate

use std::fmt;

use failure::{Backtrace, Context, Fail};

/// An alias for lexer results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for lexer errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Unexpected end of input
    #[fail(display = "unexpected end of input")]
    EOF,

    /// An illegal character was found
    #[fail(display = "illegal character input: {}", _0)]
    IllegalCharacter(char),

    /// An illegal state was reached
    #[fail(display = "illegal state: {}", _0)]
    IllegalState(&'static str),

    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// An unclosed list was found
    #[fail(display = "unclosed list, missing ')'")]
    UnclosedList,

    /// An unclosed quoted string was found
    #[fail(display = "unclosed quoted string")]
    UnclosedQuotedString,

    /// An unrecognized character was found
    #[fail(display = "unrecognized character input: {}", _0)]
    UnrecognizedChar(char),

    /// An unrecognized dollar content was found
    #[fail(display = "unrecognized dollar content: {}", _0)]
    UnrecognizedDollar(String),

    /// An unrecognized octet was found
    #[fail(display = "unrecognized octet: {:x}", _0)]
    UnrecognizedOctet(u32),
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match *self {
            EOF => EOF,
            IllegalCharacter(c) => IllegalCharacter(c),
            IllegalState(s) => IllegalState(s),
            Message(msg) => Message(msg),
            UnclosedList => UnclosedList,
            UnclosedQuotedString => UnclosedQuotedString,
            UnrecognizedChar(c) => UnrecognizedChar(c),
            UnrecognizedDollar(ref s) => UnrecognizedDollar(s.clone()),
            UnrecognizedOctet(o) => UnrecognizedOctet(o),
        }
    }
}

/// The error type for lexer errors that get returned in the crate
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
