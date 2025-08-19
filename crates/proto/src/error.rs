// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
#[cfg(feature = "std")]
use std::{io, sync};

#[cfg(feature = "backtrace")]
pub use backtrace::Backtrace as ExtBacktrace;
use enum_as_inner::EnumAsInner;
#[cfg(feature = "backtrace")]
use once_cell::sync::Lazy;
use thiserror::Error;
use tracing::debug;

#[cfg(feature = "__dnssec")]
use crate::dnssec::Proof;
#[cfg(any(feature = "dnssec-aws-lc-rs", feature = "dnssec-ring"))]
use crate::dnssec::ring_like::Unspecified;
use crate::op::{Header, Query, ResponseCode};
use crate::rr::{Record, RecordType, rdata::SOA, resource::RecordRef};
use crate::serialize::binary::DecodeError;
use crate::xfer::DnsResponse;

/// Boolean for checking if backtrace is enabled at runtime
#[cfg(feature = "backtrace")]
pub static ENABLE_BACKTRACE: Lazy<bool> = Lazy::new(|| {
    use std::env;
    let bt = env::var("RUST_BACKTRACE");
    matches!(bt.as_ref().map(|s| s as &str), Ok("full") | Ok("1"))
});

/// Generate a backtrace
///
/// If RUST_BACKTRACE is 1 or full then this will return Some(Backtrace), otherwise, NONE.
#[cfg(feature = "backtrace")]
#[macro_export]
macro_rules! trace {
    () => {{
        use $crate::ExtBacktrace as Backtrace;

        if *$crate::ENABLE_BACKTRACE {
            Some(Backtrace::new())
        } else {
            None
        }
    }};
}

/// An alias for results returned by functions of this crate
pub(crate) type ProtoResult<T> = ::core::result::Result<T, ProtoError>;

/// The error kind for errors that get returned in the crate
#[derive(Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum ProtoErrorKind {
    /// Query count is not one
    #[error("there should only be one query per request, got: {0}")]
    BadQueryCount(usize),

    /// A UDP response was received with an incorrect transaction id, likely indicating a
    /// cache-poisoning attempt.
    #[error("bad transaction id received")]
    BadTransactionId,

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
    #[non_exhaustive]
    #[error("char data length exceeds {max}: {len}")]
    CharacterDataTooLong {
        /// Specified maximum
        max: usize,
        /// Actual length
        len: usize,
    },

    /// Overlapping labels
    #[non_exhaustive]
    #[error("overlapping labels name {label} other {other}")]
    LabelOverlapsWithOther {
        /// Start of the label that is overlaps
        label: usize,
        /// Start of the other label
        other: usize,
    },

    /// No Records and there is a corresponding DNSSEC Proof for NSEC
    #[cfg(feature = "__dnssec")]
    #[non_exhaustive]
    #[error("DNSSEC Negative Record Response for {query}, {proof}")]
    Nsec {
        /// Query for which the NSEC was returned
        query: Box<Query>,
        /// Response for which the NSEC was returned
        response: Box<DnsResponse>,
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
        /// Error that occurred while parsing the Message
        error: Box<ProtoError>,
    },

    /// The length of rdata read was not as expected
    #[non_exhaustive]
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

    /// Pointer points to an index within or after the current name
    #[non_exhaustive]
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

    /// Maximum record limit was exceeded
    #[error("maximum record limit for {record_type} exceeded: {count} records")]
    MaxRecordLimitExceeded {
        /// number of records
        count: usize,
        /// The record type that triggered the error.
        record_type: RecordType,
    },

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// No resolvers available
    #[error("no connections available")]
    NoConnections,

    /// Not all records were able to be written
    #[non_exhaustive]
    #[error("not all records could be written, wrote: {count}")]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: usize,
    },

    /// No records were found for a query
    #[error("no records found for {:?}", .0.query)]
    NoRecordsFound(NoRecords),

    /// An unknown algorithm type was found
    #[error("algorithm type value unknown: {0}")]
    UnknownAlgorithmTypeValue(u8),

    /// An unknown digest type was found
    #[error("digest type value unknown: {0}")]
    UnknownDigestTypeValue(u8),

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
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    Io(Arc<io::Error>),

    /// Any sync poised error
    #[error("lock poisoned error")]
    Poisoned,

    /// A request was Refused due to some access check
    #[error("request refused")]
    RequestRefused,

    /// Received an error response code from the server
    #[error("error response: {0}")]
    ResponseCode(ResponseCode),

    /// A ring error
    #[cfg(feature = "__dnssec")]
    #[error("ring error: {0}")]
    Ring(#[from] Unspecified),

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
    Utf8(#[from] core::str::Utf8Error),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    FromUtf8(#[from] alloc::string::FromUtf8Error),

    /// An int parsing error
    #[error("error parsing int")]
    ParseInt(#[from] core::num::ParseIntError),

    /// A Quinn (Quic) connection error occurred
    #[cfg(feature = "__quic")]
    #[error("error creating quic connection: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    /// A Quinn (QUIC) connection error occurred
    #[cfg(feature = "__quic")]
    #[error("error with quic connection: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),

    /// A Quinn (QUIC) write error occurred
    #[cfg(feature = "__quic")]
    #[error("error writing to quic connection: {0}")]
    QuinnWriteError(#[from] quinn::WriteError),

    /// A Quinn (QUIC) read error occurred
    #[cfg(feature = "__quic")]
    #[error("error writing to quic read: {0}")]
    QuinnReadError(#[from] quinn::ReadExactError),

    /// A Quinn (QUIC) stream error occurred
    #[cfg(feature = "__quic")]
    #[error("referenced a closed QUIC stream: {0}")]
    QuinnStreamError(#[from] quinn::ClosedStream),

    /// A Quinn (QUIC) configuration error occurred
    #[cfg(feature = "__quic")]
    #[error("error constructing quic configuration: {0}")]
    QuinnConfigError(#[from] quinn::ConfigError),

    /// QUIC TLS config must include an AES-128-GCM cipher suite
    #[cfg(feature = "__quic")]
    #[error("QUIC TLS config must include an AES-128-GCM cipher suite")]
    QuinnTlsConfigError(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    /// Unknown QUIC stream used
    #[cfg(feature = "__quic")]
    #[error("an unknown quic stream was used")]
    QuinnUnknownStreamError,

    /// A quic message id should always be 0
    #[cfg(feature = "__quic")]
    #[error("quic messages should always be 0, got: {0}")]
    QuicMessageIdNot0(u16),

    /// A Rustls error occurred
    #[cfg(feature = "__tls")]
    #[error("rustls construction error: {0}")]
    RustlsError(#[from] rustls::Error),

    /// Case randomization is enabled, and a server did not echo a query name back with the same
    /// case.
    #[error("case of query name in response did not match")]
    QueryCaseMismatch,
}

impl From<NoRecords> for ProtoErrorKind {
    fn from(no_records: NoRecords) -> Self {
        Self::NoRecordsFound(no_records)
    }
}

/// Response where no records were found
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NoRecords {
    /// The query for which no records were found.
    pub query: Box<Query>,
    /// If an SOA is present, then this is an authoritative response or a referral to another nameserver, see the negative_type field.
    pub soa: Option<Box<Record<SOA>>>,
    /// Nameservers may be present in addition to or in lieu of an SOA for a referral
    /// The tuple struct layout is vec[(Nameserver, [vec of glue records])]
    pub ns: Option<Arc<[ForwardNSData]>>,
    /// negative ttl, as determined from DnsResponse::negative_ttl
    ///  this will only be present if the SOA was also present.
    pub negative_ttl: Option<u32>,
    /// ResponseCode, if `NXDOMAIN`, the domain does not exist (and no other types).
    ///   If `NoError`, then the domain exists but there exist either other types at the same label, or subzones of that label.
    pub response_code: ResponseCode,
    /// Authority records from the query. These are important to preserve for DNSSEC validation.
    pub authorities: Option<Arc<[Record]>>,
}

impl NoRecords {
    /// Construct a new [`NoRecords`] from a query and a response code
    pub fn new(query: impl Into<Box<Query>>, response_code: ResponseCode) -> Self {
        Self {
            query: query.into(),
            soa: None,
            ns: None,
            negative_ttl: None,
            response_code,
            authorities: None,
        }
    }
}

impl From<AuthorityData> for NoRecords {
    fn from(value: AuthorityData) -> Self {
        let response_code = match value.is_nx_domain() {
            true => ResponseCode::NXDomain,
            false => ResponseCode::NoError,
        };

        Self {
            query: value.query,
            soa: value.soa,
            ns: None,
            negative_ttl: None,
            response_code,
            authorities: value.authorities,
        }
    }
}

/// Data from the authority section of a response.
#[derive(Clone, Debug)]
pub struct AuthorityData {
    /// Query
    pub query: Box<Query>,
    /// SOA
    pub soa: Option<Box<Record<SOA>>>,
    /// No records found?
    no_records_found: bool,
    /// IS nx domain?
    nx_domain: bool,
    /// Authority records
    pub authorities: Option<Arc<[Record]>>,
}

impl AuthorityData {
    /// Construct a new AuthorityData
    pub fn new(
        query: Box<Query>,
        soa: Option<Box<Record<SOA>>>,
        no_records_found: bool,
        nx_domain: bool,
        authorities: Option<Arc<[Record]>>,
    ) -> Self {
        Self {
            query,
            soa,
            no_records_found,
            nx_domain,
            authorities,
        }
    }

    /// are there records?
    pub fn is_no_records_found(&self) -> bool {
        self.no_records_found
    }

    /// is this nxdomain?
    pub fn is_nx_domain(&self) -> bool {
        self.nx_domain
    }
}

/// Data needed to process a NS-record-based referral.
#[derive(Clone, Debug)]
pub struct ForwardNSData {
    /// The referant NS record
    pub ns: Record,
    /// Any glue records associated with the referant NS record.
    pub glue: Arc<[Record]>,
}

/// The error type for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub struct ProtoError {
    /// Kind of error that occurred
    pub kind: ProtoErrorKind,
    /// Backtrace to the source of the error
    #[cfg(feature = "backtrace")]
    pub backtrack: Option<ExtBacktrace>,
}

impl ProtoError {
    /// Get the kind of the error
    #[inline]
    pub fn kind(&self) -> &ProtoErrorKind {
        &self.kind
    }

    /// If this is a ProtoErrorKind::Busy
    #[inline]
    pub fn is_busy(&self) -> bool {
        matches!(self.kind, ProtoErrorKind::Busy)
    }

    /// Returns true if this error represents NoConnections
    #[inline]
    pub fn is_no_connections(&self) -> bool {
        matches!(self.kind, ProtoErrorKind::NoConnections)
    }

    /// Returns true if the domain does not exist
    #[inline]
    pub fn is_nx_domain(&self) -> bool {
        matches!(
            self.kind,
            ProtoErrorKind::NoRecordsFound(NoRecords {
                response_code: ResponseCode::NXDomain,
                ..
            })
        )
    }

    /// Returns true if the error represents NoRecordsFound
    #[inline]
    pub fn is_no_records_found(&self) -> bool {
        matches!(self.kind, ProtoErrorKind::NoRecordsFound { .. })
    }

    /// Returns the SOA record, if the error contains one
    #[inline]
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self.kind {
            ProtoErrorKind::NoRecordsFound(NoRecords { soa, .. }) => soa,
            _ => None,
        }
    }

    /// Returns true if this is a std::io::Error
    #[inline]
    #[cfg(feature = "std")]
    pub fn is_io(&self) -> bool {
        matches!(self.kind, ProtoErrorKind::Io(..))
    }

    #[cfg(feature = "std")]
    pub(crate) fn as_dyn(&self) -> &(dyn std::error::Error + 'static) {
        self
    }

    /// A conversion to determine if the response is an error
    pub fn from_response(response: DnsResponse) -> Result<DnsResponse, Self> {
        use ResponseCode::*;
        debug!("response: {}", *response);

        match response.response_code() {
                Refused => Err(Self::from(ProtoErrorKind::RequestRefused)),
                code @ ServFail
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
                | code @ BADCOOKIE => Err(Self::from(ProtoErrorKind::ResponseCode(code))),
                // Some NXDOMAIN responses contain CNAME referrals, that will not be an error
                code @ NXDomain |
                // No answers are available, CNAME referrals are not failures
                code @ NoError
                if !response.contains_answer() && !response.truncated() => {
                    // TODO: if authoritative, this is cacheable, store a TTL (currently that requires time, need a "now" here)
                    // let valid_until = if response.authoritative() { now + response.negative_ttl() };
                    let soa = response.soa().as_ref().map(RecordRef::to_owned);

                    // Collect any referral nameservers and associated glue records
                    let mut referral_name_servers = vec![];
                    for ns in response.authorities().iter().filter(|ns| ns.record_type() == RecordType::NS) {
                        let glue = response
                            .additionals()
                            .iter()
                            .filter_map(|record| {
                                if let Some(ns_data) = ns.data().as_ns() {
                                    if *record.name() == **ns_data &&
                                       (record.data().as_a().is_some() || record.data().as_aaaa().is_some()) {
                                           return Some(Record::to_owned(record));
                                       }
                                }

                                None
                            })
                            .collect::<Vec<Record>>();
                        referral_name_servers.push(ForwardNSData { ns: Record::to_owned(ns), glue: glue.into() })
                    }

                    let option_ns = if !referral_name_servers.is_empty() {
                        Some(referral_name_servers.into())
                    } else {
                        None
                    };

                    let authorities = if !response.authorities().is_empty() {
                        Some(response.authorities().to_owned().into())
                    } else {
                        None
                    };

                    let negative_ttl = response.negative_ttl();
                    let query = response.into_message().take_queries().drain(..).next().unwrap_or_default();

                    let error_kind = ProtoErrorKind::NoRecordsFound(NoRecords {
                        query: Box::new(query),
                        soa: soa.map(Box::new),
                        ns: option_ns,
                        negative_ttl,
                        response_code: code,
                        authorities,
                    });

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
                return Ordering::Equal;
            }
            (ProtoErrorKind::NoRecordsFound { .. }, _) => return Ordering::Greater,
            (_, ProtoErrorKind::NoRecordsFound { .. }) => return Ordering::Less,
            _ => (),
        }

        match (kind, other) {
            #[cfg(feature = "std")]
            (ProtoErrorKind::Io { .. }, ProtoErrorKind::Io { .. }) => return Ordering::Equal,
            #[cfg(feature = "std")]
            (ProtoErrorKind::Io { .. }, _) => return Ordering::Greater,
            #[cfg(feature = "std")]
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

    /// Whether the query should be retried after this error
    pub fn should_retry(&self) -> bool {
        !matches!(
            self.kind(),
            ProtoErrorKind::NoConnections | ProtoErrorKind::NoRecordsFound { .. }
        )
    }

    /// Whether this error should count as an attempt
    pub fn attempted(&self) -> bool {
        !matches!(self.kind(), ProtoErrorKind::Busy)
    }
}

impl fmt::Display for ProtoError {
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

impl<E: Into<ProtoErrorKind>> From<E> for ProtoError {
    fn from(error: E) -> Self {
        Self {
            kind: error.into(),
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

#[cfg(feature = "std")]
impl From<io::Error> for ProtoErrorKind {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(e.into()),
        }
    }
}

#[cfg(feature = "std")]
impl<T> From<sync::PoisonError<T>> for ProtoError {
    fn from(_e: sync::PoisonError<T>) -> Self {
        ProtoErrorKind::Poisoned.into()
    }
}

#[cfg(feature = "std")]
impl From<ProtoError> for io::Error {
    fn from(e: ProtoError) -> Self {
        match e.kind() {
            ProtoErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::other(e),
        }
    }
}

impl From<ProtoError> for String {
    fn from(e: ProtoError) -> Self {
        e.to_string()
    }
}

#[cfg(feature = "wasm-bindgen")]
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
            BadTransactionId => BadTransactionId,
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
            IncorrectRDataLengthRead { read, len } => IncorrectRDataLengthRead { read, len },
            LabelBytesTooLong(len) => LabelBytesTooLong(len),
            PointerNotPriorToLabel { idx, ptr } => PointerNotPriorToLabel { idx, ptr },
            MaxBufferSizeExceeded(max) => MaxBufferSizeExceeded(max),
            MaxRecordLimitExceeded { count, record_type } => {
                MaxRecordLimitExceeded { count, record_type }
            }
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),
            NoConnections => NoConnections,
            NotAllRecordsWritten { count } => NotAllRecordsWritten { count },
            NoRecordsFound(ref inner) => NoRecordsFound(inner.clone()),
            RequestRefused => RequestRefused,
            ResponseCode(code) => ResponseCode(code),
            #[cfg(feature = "__dnssec")]
            Nsec {
                ref query,
                ref response,
                proof,
            } => Nsec {
                query: query.clone(),
                response: response.clone(),
                proof,
            },
            UnknownAlgorithmTypeValue(value) => UnknownAlgorithmTypeValue(value),
            UnknownDigestTypeValue(value) => UnknownDigestTypeValue(value),
            UnknownDnsClassStr(ref value) => UnknownDnsClassStr(value.clone()),
            UnknownDnsClassValue(value) => UnknownDnsClassValue(value),
            UnknownRecordTypeStr(ref value) => UnknownRecordTypeStr(value.clone()),
            UnknownRecordTypeValue(value) => UnknownRecordTypeValue(value),
            UnrecognizedLabelCode(value) => UnrecognizedLabelCode(value),
            UnrecognizedNsec3Flags(flags) => UnrecognizedNsec3Flags(flags),
            UnrecognizedCsyncFlags(flags) => UnrecognizedCsyncFlags(flags),
            #[cfg(feature = "std")]
            Io(ref e) => Io(e.clone()),
            Poisoned => Poisoned,
            #[cfg(feature = "__dnssec")]
            Ring(ref _e) => Ring(Unspecified),
            Timeout => Timeout,
            Timer => Timer,
            UrlParsing(ref e) => UrlParsing(*e),
            Utf8(ref e) => Utf8(*e),
            FromUtf8(ref e) => FromUtf8(e.clone()),
            ParseInt(ref e) => ParseInt(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnConnect(ref e) => QuinnConnect(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnConnection(ref e) => QuinnConnection(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnWriteError(ref e) => QuinnWriteError(e.clone()),
            #[cfg(feature = "__quic")]
            QuicMessageIdNot0(val) => QuicMessageIdNot0(val),
            #[cfg(feature = "__quic")]
            QuinnReadError(ref e) => QuinnReadError(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnStreamError(ref e) => QuinnStreamError(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnConfigError(ref e) => QuinnConfigError(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnTlsConfigError(ref e) => QuinnTlsConfigError(e.clone()),
            #[cfg(feature = "__quic")]
            QuinnUnknownStreamError => QuinnUnknownStreamError,
            #[cfg(feature = "__tls")]
            RustlsError(ref e) => RustlsError(e.clone()),
            QueryCaseMismatch => QueryCaseMismatch,
        }
    }
}
