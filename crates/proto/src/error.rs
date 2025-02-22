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
pub use backtrace::Backtrace as ExtBacktrace;
use enum_as_inner::EnumAsInner;
#[cfg(feature = "backtrace")]
use once_cell::sync::Lazy;
#[cfg(feature = "dnssec-ring")]
use ring::error::Unspecified;
use thiserror::Error;
use tracing::debug;

#[cfg(feature = "dnssec-ring")]
use crate::dnssec::Proof;
use crate::op::{Header, Query, ResponseCode};
use crate::rr::{Record, RecordType, domain::Name, rdata::SOA, resource::RecordRef};
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
pub(crate) type ProtoResult<T> = ::std::result::Result<T, ProtoError>;

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
    #[cfg(feature = "dnssec-ring")]
    #[error("DNSSEC Negative Record Response for {query}, {proof}")]
    Nsec {
        /// Query for which the NSEC was returned
        query: Box<Query>,
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
        /// Nameservers may be present in addition to or in lieu of an SOA for a referral
        /// The tuple struct layout is vec[(Nameserver, [vec of glue records])]
        ns: Option<Arc<[ForwardNSData]>>,
        /// negative ttl, as determined from DnsResponse::negative_ttl
        ///  this will only be present if the SOA was also present.
        negative_ttl: Option<u32>,
        /// ResponseCode, if `NXDOMAIN`, the domain does not exist (and no other types).
        ///   If `NoError`, then the domain exists but there exist either other types at the same label, or subzones of that label.
        response_code: ResponseCode,
        /// If we trust `NXDOMAIN` errors from this server
        trusted: bool,
        /// Authority records from the query. These are important to preserve for DNSSEC validation.
        authorities: Option<Arc<[Record]>>,
    },

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
    #[error("io error: {0}")]
    Io(Arc<io::Error>),

    /// Any sync poised error
    #[error("lock poisoned error")]
    Poisoned,

    /// A request was Refused due to some access check
    #[error("request refused")]
    RequestRefused,

    /// A ring error
    #[cfg(feature = "dnssec-ring")]
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
    Utf8(#[from] std::str::Utf8Error),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// An int parsing error
    #[error("error parsing int")]
    ParseInt(#[from] std::num::ParseIntError),

    /// A Quinn (Quic) connection error occurred
    #[cfg(feature = "dns-over-quic")]
    #[error("error creating quic connection: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    /// A Quinn (QUIC) connection error occurred
    #[cfg(feature = "dns-over-quic")]
    #[error("error with quic connection: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),

    /// A Quinn (QUIC) write error occurred
    #[cfg(feature = "dns-over-quic")]
    #[error("error writing to quic connection: {0}")]
    QuinnWriteError(#[from] quinn::WriteError),

    /// A Quinn (QUIC) read error occurred
    #[cfg(feature = "dns-over-quic")]
    #[error("error writing to quic read: {0}")]
    QuinnReadError(#[from] quinn::ReadExactError),

    /// A Quinn (QUIC) read error occurred
    #[cfg(feature = "dns-over-quic")]
    #[error("referenced a closed QUIC stream: {0}")]
    QuinnStreamError(#[from] quinn::ClosedStream),

    /// A Quinn (QUIC) configuration error occurred
    #[cfg(feature = "dns-over-quic")]
    #[error("error constructing quic configuration: {0}")]
    QuinnConfigError(#[from] quinn::ConfigError),

    /// QUIC TLS config must include an AES-128-GCM cipher suite
    #[cfg(feature = "dns-over-quic")]
    #[error("QUIC TLS config must include an AES-128-GCM cipher suite")]
    QuinnTlsConfigError(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    /// Unknown QUIC stream used
    #[cfg(feature = "dns-over-quic")]
    #[error("an unknown quic stream was used")]
    QuinnUnknownStreamError,

    /// A quic message id should always be 0
    #[cfg(feature = "dns-over-quic")]
    #[error("quic messages should always be 0, got: {0}")]
    QuicMessageIdNot0(u16),

    /// A Rustls error occurred
    #[cfg(feature = "rustls")]
    #[error("rustls construction error: {0}")]
    RustlsError(#[from] rustls::Error),
}

/// Data needed to process a SOA-record-based referral.
#[derive(Clone, Debug)]
pub struct ForwardData {
    /// Query
    pub query: Box<Query>,
    /// Name
    pub name: Name,
    /// SOA
    pub soa: Box<Record<SOA>>,
    /// No records found?
    no_records_found: bool,
    /// IS nx domain?
    nx_domain: bool,
    /// Authority records
    pub authorities: Option<Arc<[Record]>>,
}

impl ForwardData {
    /// Construct a new ForwardData
    pub fn new(
        query: Box<Query>,
        name: Name,
        soa: Box<Record<SOA>>,
        no_records_found: bool,
        nx_domain: bool,
        authorities: Option<Arc<[Record]>>,
    ) -> Self {
        Self {
            query,
            name,
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
    pub kind: Box<ProtoErrorKind>,
    /// Backtrace to the source of the error
    #[cfg(feature = "backtrace")]
    pub backtrack: Option<ExtBacktrace>,
}

impl ProtoError {
    /// Constructor to NX type errors
    #[inline]
    pub fn nx_error(
        query: Box<Query>,
        soa: Option<Box<Record<SOA>>>,
        ns: Option<Arc<[ForwardNSData]>>,
        negative_ttl: Option<u32>,
        response_code: ResponseCode,
        trusted: bool,
        authorities: Option<Arc<[Record]>>,
    ) -> Self {
        ProtoErrorKind::NoRecordsFound {
            query,
            soa,
            ns,
            negative_ttl,
            response_code,
            trusted,
            authorities,
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

    /// Returns true if the domain does not exist
    #[inline]
    pub fn is_nx_domain(&self) -> bool {
        matches!(
            *self.kind,
            ProtoErrorKind::NoRecordsFound {
                response_code: ResponseCode::NXDomain,
                ..
            }
        )
    }

    /// Returns true if the error represents NoRecordsFound
    #[inline]
    pub fn is_no_records_found(&self) -> bool {
        matches!(*self.kind, ProtoErrorKind::NoRecordsFound { .. })
    }

    /// Returns the SOA record, if the error contains one
    #[inline]
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match *self.kind {
            ProtoErrorKind::NoRecordsFound { soa, .. } => soa,
            _ => None,
        }
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
        debug!("response: {}", *response);

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
                    let soa = response.soa().as_ref().map(RecordRef::to_owned);
                    let query = response.queries().iter().next().cloned().unwrap_or_default();
                    let error_kind = ProtoErrorKind::NoRecordsFound {
                        query: Box::new(query),
                        ns: None,
                        soa: soa.map(Box::new),
                        negative_ttl: None,
                        response_code: code,
                        // This is marked as false as these are all potentially temporary error Response codes about
                        //   the client and server interaction, and do not pertain to record existence.
                        trusted: false,
                        authorities: None,
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
                    let soa = response.soa().as_ref().map(RecordRef::to_owned);

                    // Collect any referral nameservers and associated glue records
                    let mut referral_name_servers = vec![];
                    for ns in response.name_servers().iter().filter(|ns| ns.record_type() == RecordType::NS) {
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

                    let authorities = if ! response.name_servers().is_empty() {
                        Some(response.name_servers().to_owned().into())
                    } else {
                        None
                    };

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
                        ns: option_ns,
                        negative_ttl,
                        response_code: code,
                        trusted,
                        authorities,
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
                return Ordering::Equal;
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
        match e.kind() {
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
            NoError => NoError,
            NotAllRecordsWritten { count } => NotAllRecordsWritten { count },
            NoRecordsFound {
                ref query,
                ref soa,
                ref ns,
                negative_ttl,
                response_code,
                trusted,
                ref authorities,
            } => NoRecordsFound {
                query: query.clone(),
                soa: soa.clone(),
                ns: ns.clone(),
                negative_ttl,
                response_code,
                trusted,
                authorities: authorities.clone(),
            },
            RequestRefused => RequestRefused,
            #[cfg(feature = "dnssec-ring")]
            Nsec { ref query, proof } => Nsec {
                query: query.clone(),
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
            Io(ref e) => Io(e.clone()),
            Poisoned => Poisoned,
            #[cfg(feature = "dnssec-ring")]
            Ring(ref _e) => Ring(Unspecified),
            Timeout => Timeout,
            Timer => Timer,
            UrlParsing(ref e) => UrlParsing(*e),
            Utf8(ref e) => Utf8(*e),
            FromUtf8(ref e) => FromUtf8(e.clone()),
            ParseInt(ref e) => ParseInt(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnConnect(ref e) => QuinnConnect(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnConnection(ref e) => QuinnConnection(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnWriteError(ref e) => QuinnWriteError(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuicMessageIdNot0(val) => QuicMessageIdNot0(val),
            #[cfg(feature = "dns-over-quic")]
            QuinnReadError(ref e) => QuinnReadError(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnStreamError(ref e) => QuinnStreamError(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnConfigError(ref e) => QuinnConfigError(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnTlsConfigError(ref e) => QuinnTlsConfigError(e.clone()),
            #[cfg(feature = "dns-over-quic")]
            QuinnUnknownStreamError => QuinnUnknownStreamError,
            #[cfg(feature = "rustls")]
            RustlsError(ref e) => RustlsError(e.clone()),
        }
    }
}
