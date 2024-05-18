// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use std::cmp::Ordering;
use std::sync::Arc;
use std::{fmt, io, sync};

#[cfg(feature = "backtrace")]
#[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
pub use backtrace::Backtrace as ExtBacktrace;
use enum_as_inner::EnumAsInner;
#[cfg(feature = "backtrace")]
use once_cell::sync::Lazy;
use thiserror::Error;
use tracing::debug;

use crate::op::{Header, Query, ResponseCode};

#[cfg(feature = "dnssec")]
use crate::rr::dnssec::{rdata::tsig::TsigAlgorithm, Proof};
use crate::rr::{rdata::SOA, resource::RecordRef, Record};
use crate::serialize::binary::DecodeError;
use crate::xfer::DnsResponse;

/// Boolean for checking if backtrace is enabled at runtime
#[cfg(feature = "backtrace")]
#[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
pub static ENABLE_BACKTRACE: Lazy<bool> = Lazy::new(|| {
    use std::env;
    let bt = env::var("RUST_BACKTRACE");
    matches!(bt.as_ref().map(|s| s as &str), Ok("full") | Ok("1"))
});

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

    /// No Records and there is a corresponding DNSSEC Proof for NSEC
    #[cfg(feature = "dnssec")]
    #[error("DNSSEC Negative Record Response for {query}, {proof}")]
    Nsec {
        /// Query for which the NSEC was returned
        query: crate::op::Query,
        /// DNSSEC proof of the record
        proof: Proof,
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

    /// No resolvers available
    #[error("no connections available")]
    NoConnections,

    /// No error was specified
    #[error("no error specified")]
    NoError,

    /// Not all records were able to be written
    #[error("not all records could be written, wrote: {count}")]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: usize,
    },

    /// No records were found for a query
    #[error("no records found for {:?}", query)]
    NoRecordsFound {
        /// The query for which no records were found.
        query: Box<Query>,
        /// If an SOA is present, then this is an authoritative response or a referral to another nameserver, see the negative_type field.
        soa: Option<Box<Record<SOA>>>,
        /// negative ttl, as determined from DnsResponse::negative_ttl
        ///  this will only be present if the SOA was also present.
        negative_ttl: Option<u32>,
        /// ResponseCode, if `NXDOMAIN`, the domain does not exist (and no other types).
        ///   If `NoError`, then the domain exists but there exist either other types at the same label, or subzones of that label.
        response_code: ResponseCode,
        /// If we trust `NXDOMAIN` errors from this server
        trusted: bool,
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
    Io(Arc<io::Error>),

    /// Any sync poised error
    #[error("lock poisoned error")]
    Poisoned,

    /// A request was Refused due to some access check
    #[error("request refused")]
    RequestRefused,

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

    /// Tsig key verification failed
    #[error("Tsig key wrong key error")]
    TsigWrongKey,

    /// Tsig unsupported mac algorithm
    /// Supported algorithm documented in `TsigAlgorithm::supported` function.
    #[cfg(feature = "dnssec")]
    #[error("Tsig unsupported mac algorithm")]
    TsigUnsupportedMacAlgorithm(TsigAlgorithm),

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

    /// A Quinn (Quic) connection error occurred
    #[cfg(feature = "quinn")]
    #[error("error creating quic connection: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    /// A Quinn (QUIC) connection error occurred
    #[cfg(feature = "quinn")]
    #[error("error with quic connection: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),

    /// A Quinn (QUIC) write error occurred
    #[cfg(feature = "quinn")]
    #[error("error writing to quic connection: {0}")]
    QuinnWriteError(#[from] quinn::WriteError),

    /// A Quinn (QUIC) read error occurred
    #[cfg(feature = "quinn")]
    #[error("error writing to quic read: {0}")]
    QuinnReadError(#[from] quinn::ReadExactError),

    /// A Quinn (QUIC) configuration error occurred
    #[cfg(feature = "quinn")]
    #[error("error constructing quic configuration: {0}")]
    QuinnConfigError(#[from] quinn::ConfigError),

    /// Unknown QUIC stream used
    #[cfg(feature = "quinn")]
    #[error("an unknown quic stream was used")]
    QuinnUnknownStreamError,

    /// A quic message id should always be 0
    #[cfg(feature = "quinn")]
    #[error("quic messages should always be 0, got: {0}")]
    QuicMessageIdNot0(u16),

    /// A Rustls error occurred
    #[cfg(feature = "rustls")]
    #[error("rustls construction error: {0}")]
    RustlsError(#[from] rustls::Error),

    /// No valid certificates found in the native root store.
    #[cfg(all(feature = "native-certs", not(feature = "webpki-roots")))]
    #[error("no valid certificates found in the native root store")]
    NativeCerts,
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
    /// Constructor to NX type errors
    #[inline]
    pub fn nx_error(
        query: Query,
        soa: Option<Record<SOA>>,
        negative_ttl: Option<u32>,
        response_code: ResponseCode,
        trusted: bool,
    ) -> Self {
        ProtoErrorKind::NoRecordsFound {
            query: Box::new(query),
            soa: soa.map(Box::new),
            negative_ttl,
            response_code,
            trusted,
        }
        .into()
    }

    /// Get the kind of the error
    #[inline]
    pub fn kind(&self) -> &ProtoErrorKind {
        &self.kind
    }

    /// If this is a ProtoErrorKind::Busy
    #[inline]
    pub fn is_busy(&self) -> bool {
        matches!(*self.kind, ProtoErrorKind::Busy)
    }

    /// Returns true if this error represents NoConnections
    #[inline]
    pub fn is_no_connections(&self) -> bool {
        matches!(*self.kind, ProtoErrorKind::NoConnections)
    }

    /// Returns true if this is a std::io::Error
    #[inline]
    pub fn is_io(&self) -> bool {
        matches!(*self.kind, ProtoErrorKind::Io(..))
    }

    pub(crate) fn as_dyn(&self) -> &(dyn std::error::Error + 'static) {
        self
    }

    /// A conversion to determine if the response is an error
    pub fn from_response(response: DnsResponse, trust_nx: bool) -> Result<DnsResponse, Self> {
        use ResponseCode::*;
        debug!("Response:{}", *response);

        match response.response_code() {
                code @ ServFail
                | code @ Refused
                | code @ FormErr
                | code @ NotImp
                | code @ YXDomain
                | code @ YXRRSet
                | code @ NXRRSet
                | code @ NotAuth
                | code @ NotZone
                | code @ BADVERS
                | code @ BADSIG
                | code @ BADKEY
                | code @ BADTIME
                | code @ BADMODE
                | code @ BADNAME
                | code @ BADALG
                | code @ BADTRUNC
                | code @ BADCOOKIE => {
                    let response = response;
                    let soa = response.soa().as_ref().map(RecordRef::to_owned);
                    let query = response.queries().iter().next().cloned().unwrap_or_default();
                    let error_kind = ProtoErrorKind::NoRecordsFound {
                        query: Box::new(query),
                        soa: soa.map(Box::new),
                        negative_ttl: None,
                        response_code: code,
                        // This is marked as false as these are all potentially temporary error Response codes about
                        //   the client and server interaction, and do not pertain to record existence.
                        trusted: false,
                    };

                    Err(Self::from(error_kind))
                }
                // Some NXDOMAIN responses contain CNAME referrals, that will not be an error
                code @ NXDomain |
                // No answers are available, CNAME referrals are not failures
                code @ NoError
                if !response.contains_answer() && !response.truncated() => {
                    // TODO: if authoritative, this is cacheable, store a TTL (currently that requires time, need a "now" here)
                    // let valid_until = if response.authoritative() { now + response.negative_ttl() };

                    let response = response;
                    let soa = response.soa().as_ref().map(RecordRef::to_owned);
                    let negative_ttl = response.negative_ttl();
                    // Note: improperly configured servers may do recursive lookups and return bad SOA
                    // records here via AS112 (blackhole-1.iana.org. etc)
                    // Such servers should be marked not trusted, as they may break reverse lookups
                    // for local hosts.
                    let trusted = trust_nx && soa.is_some();
                    let query = response.into_message().take_queries().drain(..).next().unwrap_or_default();
                    let error_kind = ProtoErrorKind::NoRecordsFound {
                        query: Box::new(query),
                        soa: soa.map(Box::new),
                        negative_ttl,
                        response_code: code,
                        trusted,
                    };

                    Err(Self::from(error_kind))
                }
                NXDomain
                | NoError
                | Unknown(_) => Ok(response),
            }
    }

    /// Compare two errors to see if one contains a server response.
    pub fn cmp_specificity(&self, other: &Self) -> Ordering {
        let kind = self.kind();
        let other = other.kind();

        match (kind, other) {
            (ProtoErrorKind::NoRecordsFound { .. }, ProtoErrorKind::NoRecordsFound { .. }) => {
                return Ordering::Equal
            }
            (ProtoErrorKind::NoRecordsFound { .. }, _) => return Ordering::Greater,
            (_, ProtoErrorKind::NoRecordsFound { .. }) => return Ordering::Less,
            _ => (),
        }

        match (kind, other) {
            (ProtoErrorKind::Io { .. }, ProtoErrorKind::Io { .. }) => return Ordering::Equal,
            (ProtoErrorKind::Io { .. }, _) => return Ordering::Greater,
            (_, ProtoErrorKind::Io { .. }) => return Ordering::Less,
            _ => (),
        }

        match (kind, other) {
            (ProtoErrorKind::Timeout, ProtoErrorKind::Timeout) => return Ordering::Equal,
            (ProtoErrorKind::Timeout, _) => return Ordering::Greater,
            (_, ProtoErrorKind::Timeout) => return Ordering::Less,
            _ => (),
        }

        Ordering::Equal
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

impl<E> From<E> for ProtoError
where
    E: Into<ProtoErrorKind>,
{
    fn from(error: E) -> Self {
        let kind: ProtoErrorKind = error.into();

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

impl From<io::Error> for ProtoErrorKind {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(e.into()),
        }
    }
}

impl<T> From<sync::PoisonError<T>> for ProtoError {
    fn from(_e: sync::PoisonError<T>) -> Self {
        ProtoErrorKind::Poisoned.into()
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
            NoConnections => NoConnections,
            NoError => NoError,
            NotAllRecordsWritten { count } => NotAllRecordsWritten { count },
            NoRecordsFound {
                ref query,
                ref soa,
                negative_ttl,
                response_code,
                trusted,
            } => NoRecordsFound {
                query: query.clone(),
                soa: soa.clone(),
                negative_ttl,
                response_code,
                trusted,
            },
            RequestRefused => RequestRefused,
            #[cfg(feature = "dnssec")]
            Nsec { ref query, proof } => Nsec {
                query: query.clone(),
                proof,
            },
            UnknownAlgorithmTypeValue(value) => UnknownAlgorithmTypeValue(value),
            UnknownDnsClassStr(ref value) => UnknownDnsClassStr(value.clone()),
            UnknownDnsClassValue(value) => UnknownDnsClassValue(value),
            UnknownRecordTypeStr(ref value) => UnknownRecordTypeStr(value.clone()),
            UnknownRecordTypeValue(value) => UnknownRecordTypeValue(value),
            UnrecognizedLabelCode(value) => UnrecognizedLabelCode(value),
            UnrecognizedNsec3Flags(flags) => UnrecognizedNsec3Flags(flags),
            UnrecognizedCsyncFlags(flags) => UnrecognizedCsyncFlags(flags),
            Io(ref e) => Io(e.clone()),
            Poisoned => Poisoned,
            Ring(ref _e) => Ring(Unspecified),
            SSL(ref e) => Msg(format!("there was an SSL error: {e}")),
            Timeout => Timeout,
            Timer => Timer,
            #[cfg(feature = "dnssec")]
            TsigUnsupportedMacAlgorithm(ref alg) => TsigUnsupportedMacAlgorithm(alg.clone()),
            TsigWrongKey => TsigWrongKey,
            UrlParsing(ref e) => UrlParsing(*e),
            Utf8(ref e) => Utf8(*e),
            FromUtf8(ref e) => FromUtf8(e.clone()),
            ParseInt(ref e) => ParseInt(e.clone()),
            #[cfg(feature = "quinn")]
            QuinnConnect(ref e) => QuinnConnect(e.clone()),
            #[cfg(feature = "quinn")]
            QuinnConnection(ref e) => QuinnConnection(e.clone()),
            #[cfg(feature = "quinn")]
            QuinnWriteError(ref e) => QuinnWriteError(e.clone()),
            #[cfg(feature = "quinn")]
            QuicMessageIdNot0(val) => QuicMessageIdNot0(val),
            #[cfg(feature = "quinn")]
            QuinnReadError(ref e) => QuinnReadError(e.clone()),
            #[cfg(feature = "quinn")]
            QuinnConfigError(ref e) => QuinnConfigError(e.clone()),
            #[cfg(feature = "quinn")]
            QuinnUnknownStreamError => QuinnUnknownStreamError,
            #[cfg(feature = "rustls")]
            RustlsError(ref e) => RustlsError(e.clone()),
            #[cfg(all(feature = "native-certs", not(feature = "webpki-roots")))]
            NativeCerts => NativeCerts,
        }
    }
}

/// A trait marking a type which implements `From<ProtoError>` and
/// std::error::Error types as well as Clone + Send
pub trait FromProtoError: From<ProtoError> + std::error::Error + Clone {}

impl<E> FromProtoError for E where E: From<ProtoError> + std::error::Error + Clone {}

#[cfg(not(feature = "openssl"))]
use self::not_openssl::SslErrorStack;
#[cfg(not(feature = "ring"))]
use self::not_ring::{KeyRejected, Unspecified};
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(feature = "ring")]
use ring::error::{KeyRejected, Unspecified};

/// An alias for dnssec results returned by functions of this crate
pub type DnsSecResult<T> = ::std::result::Result<T, DnsSecError>;

/// The error kind for dnssec errors that get returned in the crate
#[allow(unreachable_pub)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsSecErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    // foreign
    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// A ring error
    #[error("ring error: {0}")]
    RingKeyRejected(#[from] KeyRejected),

    /// A ring error
    #[error("ring error: {0}")]
    RingUnspecified(#[from] Unspecified),

    /// An ssl error
    #[error("ssl error: {0}")]
    SSL(#[from] SslErrorStack),

    /// A request timed out
    #[error("request timed out")]
    Timeout,
}

impl Clone for DnsSecErrorKind {
    fn clone(&self) -> Self {
        use DnsSecErrorKind::*;
        match self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),

            // foreign
            Proto(proto) => Proto(proto.clone()),
            RingKeyRejected(r) => Msg(format!("Ring rejected key: {r}")),
            RingUnspecified(_r) => RingUnspecified(Unspecified),
            SSL(ssl) => Msg(format!("SSL had an error: {ssl}")),
            Timeout => Timeout,
        }
    }
}

/// The error type for dnssec errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct DnsSecError {
    kind: DnsSecErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl DnsSecError {
    /// Get the kind of the error
    pub fn kind(&self) -> &DnsSecErrorKind {
        &self.kind
    }
}

impl fmt::Display for DnsSecError {
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

impl From<DnsSecErrorKind> for DnsSecError {
    fn from(kind: DnsSecErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for DnsSecError {
    fn from(msg: &'static str) -> Self {
        DnsSecErrorKind::Message(msg).into()
    }
}

impl From<String> for DnsSecError {
    fn from(msg: String) -> Self {
        DnsSecErrorKind::Msg(msg).into()
    }
}

impl From<ProtoError> for DnsSecError {
    fn from(e: ProtoError) -> Self {
        match *e.kind() {
            ProtoErrorKind::Timeout => DnsSecErrorKind::Timeout.into(),
            _ => DnsSecErrorKind::from(e).into(),
        }
    }
}

impl From<KeyRejected> for DnsSecError {
    fn from(e: KeyRejected) -> Self {
        DnsSecErrorKind::from(e).into()
    }
}

impl From<Unspecified> for DnsSecError {
    fn from(e: Unspecified) -> Self {
        DnsSecErrorKind::from(e).into()
    }
}

impl From<SslErrorStack> for DnsSecError {
    fn from(e: SslErrorStack) -> Self {
        DnsSecErrorKind::from(e).into()
    }
}

#[doc(hidden)]
#[allow(unreachable_pub)]
#[cfg(not(feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "openssl"))))]
pub mod not_openssl {
    use std;

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

#[doc(hidden)]
#[allow(unreachable_pub)]
#[cfg(not(feature = "ring"))]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
pub mod not_ring {
    use std;

    #[derive(Clone, Copy, Debug)]
    pub struct KeyRejected;

    #[derive(Clone, Copy, Debug)]
    pub struct Unspecified;

    impl std::fmt::Display for KeyRejected {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for KeyRejected {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }

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
