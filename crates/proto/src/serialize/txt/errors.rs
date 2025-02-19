use alloc::{fmt, string::String};
use std::io;

#[cfg(feature = "backtrace")]
use crate::trace;
use crate::{
    error::{ProtoError, ProtoErrorKind},
    rr::RecordType,
    serialize::txt::Token,
};

#[cfg(feature = "backtrace")]
use backtrace::Backtrace as ExtBacktrace;
use thiserror::Error;

/// An alias for parse results returned by functions of this crate
pub type ParseResult<T> = ::core::result::Result<T, ParseError>;

/// The error kind for parse errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseErrorKind {
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
    ParseInt(#[from] core::num::ParseIntError),

    /// An error got returned by the hickory-proto crate
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

impl Clone for ParseErrorKind {
    fn clone(&self) -> Self {
        use ParseErrorKind::*;
        match self {
            CharToInt(c) => CharToInt(*c),
            Message(msg) => Message(msg),
            MissingToken(s) => MissingToken(s.clone()),
            Msg(msg) => Msg(msg.clone()),
            ParseTime(s) => ParseTime(s.clone()),
            UnexpectedToken(token) => UnexpectedToken(token.clone()),

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
pub struct ParseError {
    kind: ParseErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl ParseError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ParseErrorKind {
        &self.kind
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(backtrace) = &self.backtrack {
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

impl From<ParseErrorKind> for ParseError {
    fn from(kind: ParseErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for ParseError {
    fn from(msg: &'static str) -> Self {
        ParseErrorKind::Message(msg).into()
    }
}

impl From<String> for ParseError {
    fn from(msg: String) -> Self {
        ParseErrorKind::Msg(msg).into()
    }
}

impl From<std::net::AddrParseError> for ParseError {
    fn from(e: std::net::AddrParseError) -> Self {
        ParseErrorKind::from(e).into()
    }
}

impl From<::data_encoding::DecodeError> for ParseError {
    fn from(e: data_encoding::DecodeError) -> Self {
        ParseErrorKind::from(e).into()
    }
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => ParseErrorKind::Timeout.into(),
            _ => ParseErrorKind::from(e).into(),
        }
    }
}

impl From<LexerError> for ParseError {
    fn from(e: LexerError) -> Self {
        ParseErrorKind::from(e).into()
    }
}

impl From<core::num::ParseIntError> for ParseError {
    fn from(e: core::num::ParseIntError) -> Self {
        ParseErrorKind::from(e).into()
    }
}

impl From<ProtoError> for ParseError {
    fn from(e: ProtoError) -> Self {
        match e.kind() {
            ProtoErrorKind::Timeout => ParseErrorKind::Timeout.into(),
            _ => ParseErrorKind::from(e).into(),
        }
    }
}

impl From<core::convert::Infallible> for ParseError {
    fn from(_e: core::convert::Infallible) -> Self {
        panic!("infallible")
    }
}

impl From<ParseError> for io::Error {
    fn from(e: ParseError) -> Self {
        match e.kind() {
            ParseErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::new(io::ErrorKind::Other, e),
        }
    }
}

/// An alias for lexer results returned by functions of this crate
pub(crate) type LexerResult<T> = core::result::Result<T, LexerError>;

/// The error kind for lexer errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Error, Clone)]
#[non_exhaustive]
pub enum LexerErrorKind {
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
pub struct LexerError {
    kind: LexerErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl LexerError {
    /// Get the kind of the error
    pub fn kind(&self) -> &LexerErrorKind {
        &self.kind
    }
}

impl From<LexerErrorKind> for LexerError {
    fn from(kind: LexerErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl fmt::Display for LexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(backtrace) = &self.backtrack {
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
