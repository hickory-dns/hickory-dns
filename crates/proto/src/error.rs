// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use std::{fmt, io, sync};

use crate::rr::{Name, RecordType};

#[cfg(not(feature = "openssl"))]
use self::not_openssl::SslErrorStack;
#[cfg(not(feature = "ring"))]
use self::not_ring::Unspecified;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(feature = "ring")]
use ring::error::Unspecified;

use failure::{Backtrace, Context, Fail};
use tokio_executor::SpawnError;
use tokio_timer::Error as TimerError;
use tokio_timer::timeout::Elapsed;

/// An alias for results returned by functions of this crate
pub type ProtoResult<T> = ::std::result::Result<T, ProtoError>;

/// The error kind for errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ProtoErrorKind {
    /// An error caused by a canceled future
    #[fail(display = "future was canceled: {:?}", _0)]
    Canceled(futures::channel::oneshot::Canceled),

    /// Character data length exceeded the limit
    #[fail(display = "char data length exceeds {}: {}", _0, _1)]
    CharacterDataTooLong {
        /// Specified maximum
        max: usize,
        /// Actual length
        len: usize,
    },

    /// Overlapping labels
    #[fail(display = "overlapping labels name {} other {}", _0, _1)]
    LabelOverlapsWithOther {
        /// Start of the label that is overlaps
        label: usize,
        /// Start of the other label
        other: usize,
    },

    /// DNS protocol version doesn't have the expected version 3
    #[fail(display = "dns key value unknown, must be 3: {}", _0)]
    DnsKeyProtocolNot3(u8),

    /// A domain name was too long
    #[fail(display = "name label data exceed 255: {}", _0)]
    DomainNameTooLong(usize),

    /// EDNS resource record label is not the root label, although required
    #[fail(
        display = "edns resource record label must be the root label (.): {}",
        _0
    )]
    EdnsNameNotRoot(crate::rr::Name),

    /// The length of rdata read was not as expected
    #[fail(display = "incorrect rdata length read: {} expected: {}", read, len)]
    IncorrectRDataLengthRead {
        /// The amount of read data
        read: usize,
        /// The expected length of the data
        len: usize,
    },

    /// Label bytes exceeded the limit of 63
    #[fail(display = "label bytes exceed 63: {}", _0)]
    LabelBytesTooLong(usize),

    /// Label bytes exceeded the limit of 63
    #[fail(display = "label points to data not prior to idx: {} ptr: {}", _0, _1)]
    PointerNotPriorToLabel {
        /// index of the label containing this pointer
        idx: usize,
        /// location to which the pointer is directing
        ptr: u16,
    },

    /// The maximum buffer size was exceeded
    #[fail(display = "maximum buffer size exceeded: {}", _0)]
    MaxBufferSizeExceeded(usize),

    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[fail(display = "{}", _0)]
    Msg(String),

    /// No error was specified
    #[fail(display = "no error specified")]
    NoError,

    /// Not all records were able to be written
    #[fail(display = "not all records could be written, wrote: {}", count)]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: usize,
    },

    /// Missing rrsigs
    #[fail(
        display = "rrsigs are not present for record set name: {} record_type: {}",
        name, record_type
    )]
    RrsigsNotPresent {
        /// The record set name
        name: Name,
        /// The record type
        record_type: RecordType,
    },

    /// An unknown algorithm type was found
    #[fail(display = "algorithm type value unknown: {}", _0)]
    UnknownAlgorithmTypeValue(u8),

    /// An unknown dns class was found
    #[fail(display = "dns class string unknown: {}", _0)]
    UnknownDnsClassStr(String),

    /// An unknown dns class value was found
    #[fail(display = "dns class value unknown: {}", _0)]
    UnknownDnsClassValue(u16),

    /// An unknown record type string was found
    #[fail(display = "record type string unknown: {}", _0)]
    UnknownRecordTypeStr(String),

    /// An unknown record type value was found
    #[fail(display = "record type value unknown: {}", _0)]
    UnknownRecordTypeValue(u16),

    /// An unrecognized label code was found
    #[fail(display = "unrecognized label code: {:b}", _0)]
    UnrecognizedLabelCode(u8),

    /// Unrecognized nsec3 flags were found
    #[fail(display = "nsec3 flags should be 0b0000000*: {:b}", _0)]
    UnrecognizedNsec3Flags(u8),

    // foreign
    /// An error got returned from IO
    #[fail(display = "io error")]
    Io,

    /// Any sync poised error
    #[fail(display = "lock poisoned error")]
    Poisoned,

    /// A ring error
    #[fail(display = "ring error")]
    Ring,

    /// Tokio Spawn Error
    #[fail(display = "tokio spawn error")]
    SpawnError,

    /// An ssl error
    #[fail(display = "ssl error")]
    SSL,

    /// A tokio timer error
    #[fail(display = "timer error")]
    Timer,

    /// A request timed out
    #[fail(display = "request timed out")]
    Timeout,

    /// An url parsing error
    #[fail(display = "url parsing error")]
    UrlParsing,

    /// A utf8 parsing error
    #[fail(display = "error parsing utf8 string")]
    Utf8,
}

/// The error type for errors that get returned in the crate
#[derive(Debug)]
pub struct ProtoError {
    inner: Context<ProtoErrorKind>,
}

impl ProtoError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ProtoErrorKind {
        self.inner.get_context()
    }
}

impl Clone for ProtoError {
    fn clone(&self) -> Self {
        ProtoError {
            inner: Context::new(self.inner.get_context().clone()),
        }
    }
}

impl Fail for ProtoError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<ProtoErrorKind> for ProtoError {
    fn from(kind: ProtoErrorKind) -> ProtoError {
        ProtoError {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ProtoErrorKind>> for ProtoError {
    fn from(inner: Context<ProtoErrorKind>) -> ProtoError {
        ProtoError { inner }
    }
}

impl From<&'static str> for ProtoError {
    fn from(msg: &'static str) -> ProtoError {
        ProtoErrorKind::Message(msg).into()
    }
}

impl From<String> for ProtoError {
    fn from(msg: String) -> ProtoError {
        ProtoErrorKind::Msg(msg).into()
    }
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> ProtoError {
        match e.kind() {
            io::ErrorKind::TimedOut => e.context(ProtoErrorKind::Timeout).into(),
            _ => e.context(ProtoErrorKind::Io).into(),
        }
    }
}

impl<T> From<sync::PoisonError<T>> for ProtoError {
    fn from(_e: sync::PoisonError<T>) -> ProtoError {
        Context::new(ProtoErrorKind::Poisoned).into()
    }
}

impl From<Unspecified> for ProtoError {
    fn from(e: Unspecified) -> ProtoError {
        e.context(ProtoErrorKind::Ring).into()
    }
}

impl From<SpawnError> for ProtoError {
    fn from(e: SpawnError) -> ProtoError {
        e.context(ProtoErrorKind::SpawnError).into()
    }
}

impl From<SslErrorStack> for ProtoError {
    fn from(e: SslErrorStack) -> ProtoError {
        e.context(ProtoErrorKind::SSL).into()
    }
}

impl From<TimerError> for ProtoError {
    fn from(e: TimerError) -> ProtoError {
        e.context(ProtoErrorKind::Timer).into()
    }
}

impl From<Elapsed> for ProtoError {
    fn from(e: Elapsed) -> ProtoError {
        e.context(ProtoErrorKind::Timeout).into()
    }
}

// impl From<tokio_timer::Error<ProtoError>> for ProtoError {
//     fn from(e: tokio_timer::Error<ProtoError>) -> Self {
//         if e.is_elapsed() {
//             return ProtoError::from(ProtoErrorKind::Timeout);
//         }

//         if e.is_inner() {
//             return e.into_inner().expect("invalid state, not a ProtoError");
//         }

//         if e.is_timer() {
//             return ProtoError::from(
//                 e.into_timer()
//                     .expect("invalid state, not a tokio_timer::Error"),
//             );
//         }

//         ProtoError::from("unknown error with tokio_timer")
//     }
// }

impl From<::url::ParseError> for ProtoError {
    fn from(e: ::url::ParseError) -> ProtoError {
        e.context(ProtoErrorKind::UrlParsing).into()
    }
}

impl From<::std::str::Utf8Error> for ProtoError {
    fn from(e: ::std::str::Utf8Error) -> ProtoError {
        e.context(ProtoErrorKind::Utf8).into()
    }
}

/// Stubs for running without OpenSSL
#[cfg(not(feature = "openssl"))]
pub mod not_openssl {
    use std;

    /// SslErrorStac stub
    #[derive(Debug)]
    pub struct SslErrorStack;

    impl std::fmt::Display for SslErrorStack {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
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
pub mod not_ring {
    use std;

    /// The Unspecified error replacement
    #[derive(Debug)]
    pub struct Unspecified;

    impl std::fmt::Display for Unspecified {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
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
            ProtoErrorKind::Timeout => io::Error::new(io::ErrorKind::TimedOut, e.compat()),
            _ => io::Error::new(io::ErrorKind::Other, e.compat()),
        }
    }
}

impl From<ProtoError> for String {
    fn from(e: ProtoError) -> Self {
        e.to_string()
    }
}

impl Clone for ProtoErrorKind {
    fn clone(&self) -> Self {
        use self::ProtoErrorKind::*;
        match *self {
            Canceled(ref c) => Canceled(*c),
            CharacterDataTooLong { max, len } => CharacterDataTooLong { max, len },
            LabelOverlapsWithOther { label, other } => LabelOverlapsWithOther { label, other },
            DnsKeyProtocolNot3(protocol) => DnsKeyProtocolNot3(protocol),
            DomainNameTooLong(len) => DomainNameTooLong(len),
            EdnsNameNotRoot(ref found) => EdnsNameNotRoot(found.clone()),
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

            // foreign
            Io => Io,
            Poisoned => Poisoned,
            Ring => Ring,
            SpawnError => SpawnError,
            SSL => SSL,
            Timeout => Timeout,
            Timer => Timer,
            UrlParsing => UrlParsing,
            Utf8 => Utf8,
        }
    }
}

/// A trait marking a type which implements From<ProtoError> and
/// failure::Fail (which includes all std::error::Error types)
/// as well as Clone + Send
pub trait FromProtoError: From<ProtoError> + Fail + Clone {}

impl<E> FromProtoError for E where E: From<ProtoError> + Fail + Clone {}
