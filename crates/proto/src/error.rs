// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use std::{fmt, io, sync};

#[cfg(not(feature = "openssl"))]
use self::not_openssl::SslErrorStack;
#[cfg(not(feature = "ring"))]
use self::not_ring::Unspecified;
#[cfg(feature = "backtrace")]
#[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
pub use backtrace::Backtrace as ExtBacktrace;
use enum_as_inner::EnumAsInner;
#[cfg(feature = "backtrace")]
use lazy_static::lazy_static;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(feature = "ring")]
use ring::error::Unspecified;
use thiserror::Error;

use crate::op::Header;
use crate::rr::{Name, RecordType};
use crate::serialize::binary::DecodeError;

#[cfg(feature = "backtrace")]
#[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
lazy_static! {
    /// Boolean for checking if backtrace is enabled at runtime
    pub static ref ENABLE_BACKTRACE: bool = {
        use std::env;
        let bt = env::var("RUST_BACKTRACE");
        matches!(bt.as_ref().map(|s| s as &str), Ok("full") | Ok("1"))
    };
}

/// Generate a backtrace
///
/// If RUST_BACKTRACE is 1 or full then this will return Some(Backtrace), otherwise, NONE.
#[cfg(feature = "backtrace")]
#[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
#[macro_export]
macro_rules! trace {
    () => {{
        use $crate::error::ExtBacktrace as Backtrace;

        if *$crate::error::ENABLE_BACKTRACE {
            Some(Backtrace::new())
        } else {
            None
        }
    }};
}

/// An alias for results returned by functions of this crate
pub type ProtoResult<T> = ::std::result::Result<T, ProtoError>;

/// The error kind for errors that get returned in the crate
#[derive(Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum ProtoErrorKind {
    /// Query count is not one
    #[error("there should only be one query per request, got: {0}")]
    BadQueryCount(usize),

    /// The underlying resource is too busy
    ///
    /// This is a signal that an internal resource is too busy. The intended action should be tried
    /// again, ideally after waiting for a little while for the situation to improve. Alternatively,
    /// the action could be tried on another resource (for example, in a name server pool).
    #[error("resource too busy")]
    Busy,

    /// An error caused by a canceled future
    #[error("future was canceled: {0:?}")]
    Canceled(futures_channel::oneshot::Canceled),

    /// Character data length exceeded the limit
    #[error("char data length exceeds {max}: {len}")]
    CharacterDataTooLong {
        /// Specified maximum
        max: usize,
        /// Actual length
        len: usize,
    },

    /// Overlapping labels
    #[error("overlapping labels name {label} other {other}")]
    LabelOverlapsWithOther {
        /// Start of the label that is overlaps
        label: usize,
        /// Start of the other label
        other: usize,
    },

    /// DNS protocol version doesn't have the expected version 3
    #[error("dns key value unknown, must be 3: {0}")]
    DnsKeyProtocolNot3(u8),

    /// A domain name was too long
    #[error("name label data exceed 255: {0}")]
    DomainNameTooLong(usize),

    /// EDNS resource record label is not the root label, although required
    #[error("edns resource record label must be the root label (.): {0}")]
    EdnsNameNotRoot(crate::rr::Name),

    /// Format error in Message Parsing
    #[error("message format error: {error}")]
    FormError {
        /// Header of the bad Message
        header: Header,
        /// Error that occured while parsing the Message
        error: Box<ProtoError>,
    },

    /// An HMAC failed to verify
    #[error("hmac validation failure")]
    HmacInvalid(),

    /// The length of rdata read was not as expected
    #[error("incorrect rdata length read: {read} expected: {len}")]
    IncorrectRDataLengthRead {
        /// The amount of read data
        read: usize,
        /// The expected length of the data
        len: usize,
    },

    /// Label bytes exceeded the limit of 63
    #[error("label bytes exceed 63: {0}")]
    LabelBytesTooLong(usize),

    /// Label bytes exceeded the limit of 63
    #[error("label points to data not prior to idx: {idx} ptr: {ptr}")]
    PointerNotPriorToLabel {
        /// index of the label containing this pointer
        idx: usize,
        /// location to which the pointer is directing
        ptr: u16,
    },

    /// The maximum buffer size was exceeded
    #[error("maximum buffer size exceeded: {0}")]
    MaxBufferSizeExceeded(usize),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// No error was specified
    #[error("no error specified")]
    NoError,

    /// Not all records were able to be written
    #[error("not all records could be written, wrote: {count}")]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: usize,
    },

    /// Missing rrsigs
    #[error("rrsigs are not present for record set name: {name} record_type: {record_type}")]
    RrsigsNotPresent {
        /// The record set name
        name: Name,
        /// The record type
        record_type: RecordType,
    },

    /// An unknown algorithm type was found
    #[error("algorithm type value unknown: {0}")]
    UnknownAlgorithmTypeValue(u8),

    /// An unknown dns class was found
    #[error("dns class string unknown: {0}")]
    UnknownDnsClassStr(String),

    /// An unknown dns class value was found
    #[error("dns class value unknown: {0}")]
    UnknownDnsClassValue(u16),

    /// An unknown record type string was found
    #[error("record type string unknown: {0}")]
    UnknownRecordTypeStr(String),

    /// An unknown record type value was found
    #[error("record type value unknown: {0}")]
    UnknownRecordTypeValue(u16),

    /// An unrecognized label code was found
    #[error("unrecognized label code: {0:b}")]
    UnrecognizedLabelCode(u8),

    /// Unrecognized nsec3 flags were found
    #[error("nsec3 flags should be 0b0000000*: {0:b}")]
    UnrecognizedNsec3Flags(u8),

    /// Unrecognized csync flags were found
    #[error("csync flags should be 0b000000**: {0:b}")]
    UnrecognizedCsyncFlags(u16),

    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Any sync poised error
    #[error("lock poisoned error")]
    Poisoned,

    /// A ring error
    #[error("ring error: {0}")]
    Ring(#[from] Unspecified),

    /// An ssl error
    #[error("ssl error: {0}")]
    SSL(#[from] SslErrorStack),

    /// A tokio timer error
    #[error("timer error")]
    Timer,

    /// A request timed out
    #[error("request timed out")]
    Timeout,

    /// An url parsing error
    #[error("url parsing error")]
    UrlParsing(#[from] url::ParseError),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    Utf8(#[from] std::str::Utf8Error),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// An int parsing error
    #[error("error parsing int")]
    ParseInt(#[from] std::num::ParseIntError),
}

/// The error type for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub struct ProtoError {
    /// Kind of error that ocurred
    pub kind: Box<ProtoErrorKind>,
    /// Backtrace to the source of the error
    #[cfg(feature = "backtrace")]
    pub backtrack: Option<ExtBacktrace>,
}

impl ProtoError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ProtoErrorKind {
        &self.kind
    }

    /// If this is a ProtoErrorKind::Busy
    pub fn is_busy(&self) -> bool {
        matches!(*self.kind, ProtoErrorKind::Busy)
    }
}

impl fmt::Display for ProtoError {
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

impl From<ProtoErrorKind> for ProtoError {
    fn from(kind: ProtoErrorKind) -> Self {
        Self {
            kind: Box::new(kind),
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<DecodeError> for ProtoError {
    fn from(err: DecodeError) -> Self {
        match err {
            DecodeError::PointerNotPriorToLabel { idx, ptr } => {
                ProtoErrorKind::PointerNotPriorToLabel { idx, ptr }
            }
            DecodeError::LabelBytesTooLong(len) => ProtoErrorKind::LabelBytesTooLong(len),
            DecodeError::UnrecognizedLabelCode(code) => ProtoErrorKind::UnrecognizedLabelCode(code),
            DecodeError::DomainNameTooLong(len) => ProtoErrorKind::DomainNameTooLong(len),
            DecodeError::LabelOverlapsWithOther { label, other } => {
                ProtoErrorKind::LabelOverlapsWithOther { label, other }
            }
            _ => ProtoErrorKind::Msg(err.to_string()),
        }
        .into()
    }
}

impl From<&'static str> for ProtoError {
    fn from(msg: &'static str) -> Self {
        ProtoErrorKind::Message(msg).into()
    }
}

impl From<String> for ProtoError {
    fn from(msg: String) -> Self {
        ProtoErrorKind::Msg(msg).into()
    }
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => ProtoErrorKind::Timeout.into(),
            _ => ProtoErrorKind::from(e).into(),
        }
    }
}

impl<T> From<sync::PoisonError<T>> for ProtoError {
    fn from(_e: sync::PoisonError<T>) -> Self {
        ProtoErrorKind::Poisoned.into()
    }
}

impl From<Unspecified> for ProtoError {
    fn from(e: Unspecified) -> Self {
        ProtoErrorKind::from(e).into()
    }
}

impl From<SslErrorStack> for ProtoError {
    fn from(e: SslErrorStack) -> Self {
        ProtoErrorKind::from(e).into()
    }
}

impl From<url::ParseError> for ProtoError {
    fn from(e: url::ParseError) -> Self {
        ProtoErrorKind::from(e).into()
    }
}

impl From<std::str::Utf8Error> for ProtoError {
    fn from(e: std::str::Utf8Error) -> Self {
        ProtoErrorKind::from(e).into()
    }
}

impl From<std::string::FromUtf8Error> for ProtoError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        ProtoErrorKind::from(e).into()
    }
}

impl From<std::num::ParseIntError> for ProtoError {
    fn from(e: std::num::ParseIntError) -> Self {
        ProtoErrorKind::from(e).into()
    }
}

/// Stubs for running without OpenSSL
#[cfg(not(feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "openssl"))))]
pub mod not_openssl {
    use std;

    /// SslErrorStac stub
    #[derive(Clone, Copy, Debug)]
    pub struct SslErrorStack;

    impl std::fmt::Display for SslErrorStack {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for SslErrorStack {
        fn description(&self) -> &str {
            "openssl feature not enabled"
        }
    }
}

/// Types used without ring
#[cfg(not(feature = "ring"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "ring"))))]
pub mod not_ring {
    use std;

    /// The Unspecified error replacement
    #[derive(Clone, Copy, Debug)]
    pub struct Unspecified;

    impl std::fmt::Display for Unspecified {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for Unspecified {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }
}

impl From<ProtoError> for io::Error {
    fn from(e: ProtoError) -> Self {
        match *e.kind() {
            ProtoErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::new(io::ErrorKind::Other, e),
        }
    }
}

impl From<ProtoError> for String {
    fn from(e: ProtoError) -> Self {
        e.to_string()
    }
}

#[cfg(feature = "wasm-bindgen")]
#[cfg_attr(docsrs, doc(cfg(feature = "wasm-bindgen")))]
impl From<ProtoError> for wasm_bindgen_crate::JsValue {
    fn from(e: ProtoError) -> Self {
        js_sys::Error::new(&e.to_string()).into()
    }
}

impl Clone for ProtoErrorKind {
    fn clone(&self) -> Self {
        use self::ProtoErrorKind::*;
        match *self {
            BadQueryCount(count) => BadQueryCount(count),
            Busy => Busy,
            Canceled(ref c) => Canceled(*c),
            CharacterDataTooLong { max, len } => CharacterDataTooLong { max, len },
            LabelOverlapsWithOther { label, other } => LabelOverlapsWithOther { label, other },
            DnsKeyProtocolNot3(protocol) => DnsKeyProtocolNot3(protocol),
            DomainNameTooLong(len) => DomainNameTooLong(len),
            EdnsNameNotRoot(ref found) => EdnsNameNotRoot(found.clone()),
            FormError { header, ref error } => FormError {
                header,
                error: error.clone(),
            },
            HmacInvalid() => HmacInvalid(),
            IncorrectRDataLengthRead { read, len } => IncorrectRDataLengthRead { read, len },
            LabelBytesTooLong(len) => LabelBytesTooLong(len),
            PointerNotPriorToLabel { idx, ptr } => PointerNotPriorToLabel { idx, ptr },
            MaxBufferSizeExceeded(max) => MaxBufferSizeExceeded(max),
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),
            NoError => NoError,
            NotAllRecordsWritten { count } => NotAllRecordsWritten { count },
            RrsigsNotPresent {
                ref name,
                ref record_type,
            } => RrsigsNotPresent {
                name: name.clone(),
                record_type: *record_type,
            },
            UnknownAlgorithmTypeValue(value) => UnknownAlgorithmTypeValue(value),
            UnknownDnsClassStr(ref value) => UnknownDnsClassStr(value.clone()),
            UnknownDnsClassValue(value) => UnknownDnsClassValue(value),
            UnknownRecordTypeStr(ref value) => UnknownRecordTypeStr(value.clone()),
            UnknownRecordTypeValue(value) => UnknownRecordTypeValue(value),
            UnrecognizedLabelCode(value) => UnrecognizedLabelCode(value),
            UnrecognizedNsec3Flags(flags) => UnrecognizedNsec3Flags(flags),
            UnrecognizedCsyncFlags(flags) => UnrecognizedCsyncFlags(flags),

            // foreign
            Io(ref e) => Io(if let Some(raw) = e.raw_os_error() {
                io::Error::from_raw_os_error(raw)
            } else {
                io::Error::from(e.kind())
            }),
            Poisoned => Poisoned,
            Ring(ref _e) => Ring(Unspecified),
            SSL(ref e) => Msg(format!("there was an SSL error: {}", e)),
            Timeout => Timeout,
            Timer => Timer,
            UrlParsing(ref e) => UrlParsing(*e),
            Utf8(ref e) => Utf8(*e),
            FromUtf8(ref e) => FromUtf8(e.clone()),
            ParseInt(ref e) => ParseInt(e.clone()),
        }
    }
}

/// A trait marking a type which implements From<ProtoError> and
/// std::error::Error types as well as Clone + Send
pub trait FromProtoError: From<ProtoError> + std::error::Error + Clone {}

impl<E> FromProtoError for E where E: From<ProtoError> + std::error::Error + Clone {}
