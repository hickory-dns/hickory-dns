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
use alloc::string::String;
#[cfg(feature = "wasm-bindgen")]
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "backtrace")]
pub use backtrace::Backtrace as ExtBacktrace;
use enum_as_inner::EnumAsInner;
#[cfg(feature = "backtrace")]
use once_cell::sync::Lazy;
use thiserror::Error;
use tracing::debug;

#[cfg(feature = "__dnssec")]
use crate::dnssec::Proof;
use crate::op::{DnsResponse, Header, Query, ResponseCode};
use crate::rr::{Record, RecordType, rdata::SOA, resource::RecordRef};
use crate::serialize::binary::DecodeError;

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

    /// Returns true if the domain does not exist
    #[inline]
    pub fn is_nx_domain(&self) -> bool {
        matches!(
            self.kind,
            ProtoErrorKind::Dns(DnsError::NoRecordsFound(NoRecords {
                response_code: ResponseCode::NXDomain,
                ..
            }))
        )
    }

    /// Returns true if the error represents NoRecordsFound
    #[inline]
    pub fn is_no_records_found(&self) -> bool {
        matches!(
            self.kind,
            ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. })
        )
    }

    /// Returns the SOA record, if the error contains one
    #[inline]
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self.kind {
            ProtoErrorKind::Dns(DnsError::NoRecordsFound(NoRecords { soa, .. })) => soa,
            _ => None,
        }
    }

    /// Compare two errors to see if one contains a server response.
    pub fn cmp_specificity(&self, other: &Self) -> Ordering {
        let kind = self.kind();
        let other = other.kind();

        match (kind, other) {
            (
                ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }),
                ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }),
            ) => {
                return Ordering::Equal;
            }
            (ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. }), _) => return Ordering::Greater,
            (_, ProtoErrorKind::Dns(DnsError::NoRecordsFound { .. })) => return Ordering::Less,
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

impl From<NoRecords> for ProtoError {
    fn from(no_records: NoRecords) -> Self {
        ProtoErrorKind::Dns(DnsError::NoRecordsFound(no_records)).into()
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

#[cfg(target_os = "android")]
impl From<jni::errors::Error> for ProtoError {
    fn from(e: jni::errors::Error) -> Self {
        ProtoErrorKind::Jni(Arc::new(e)).into()
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

#[cfg(feature = "wasm-bindgen")]
impl From<ProtoError> for wasm_bindgen_crate::JsValue {
    fn from(e: ProtoError) -> Self {
        js_sys::Error::new(&e.to_string()).into()
    }
}

/// The error kind for errors that get returned in the crate
#[derive(Clone, Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum ProtoErrorKind {
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

    /// Character data length exceeded the limit
    #[non_exhaustive]
    #[error("char data length exceeds {max}: {len}")]
    CharacterDataTooLong {
        /// Specified maximum
        max: usize,
        /// Actual length
        len: usize,
    },

    /// Crypto operation failed
    #[error("crypto error: {0}")]
    #[cfg(feature = "__dnssec")]
    Crypto(&'static str),

    /// Message decoding error
    #[error("decoding error: {0}")]
    Decode(#[from] DecodeError),

    /// Semantic DNS errors
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// Format error in Message Parsing
    #[error("message format error: {error}")]
    FormError {
        /// Header of the bad Message
        header: Header,
        /// Error that occurred while parsing the Message
        error: Box<ProtoError>,
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

    /// Not all records were able to be written
    #[non_exhaustive]
    #[error("not all records could be written, wrote: {count}")]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: usize,
    },

    // foreign
    /// An error got returned from IO
    #[cfg(feature = "std")]
    #[error("io error: {0}")]
    Io(Arc<io::Error>),

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

    /// A JNI call error
    #[cfg(target_os = "android")]
    #[error("JNI call error: {0}")]
    Jni(Arc<jni::errors::Error>),
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

/// Semantic DNS errors
#[derive(Clone, Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum DnsError {
    /// Received an error response code from the server
    #[error("error response: {0}")]
    ResponseCode(ResponseCode),
    /// No records were found for a query
    #[error("no records found for {:?}", .0.query)]
    NoRecordsFound(NoRecords),
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
}

impl DnsError {
    /// A conversion to determine if the response is an error
    pub fn from_response(response: DnsResponse) -> Result<DnsResponse, Self> {
        use ResponseCode::*;
        debug!("response: {}", *response);

        match response.response_code() {
                Refused => Err(Self::ResponseCode(Refused)),
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
                | code @ BADCOOKIE => Err(Self::ResponseCode(code)),
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

                    Err(Self::NoRecordsFound(NoRecords {
                        query: Box::new(query),
                        soa: soa.map(Box::new),
                        ns: option_ns,
                        negative_ttl,
                        response_code: code,
                        authorities,
                    }))
                }
                NXDomain
                | NoError
                | Unknown(_) => Ok(response),
            }
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

/// Data needed to process a NS-record-based referral.
#[derive(Clone, Debug)]
pub struct ForwardNSData {
    /// The referant NS record
    pub ns: Record,
    /// Any glue records associated with the referant NS record.
    pub glue: Arc<[Record]>,
}
