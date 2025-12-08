// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use core::num::ParseIntError;
use std::io;
use std::sync::Arc;

#[cfg(any(feature = "__https", feature = "__h3"))]
use http::header::ToStrError;
use thiserror::Error;
use tracing::debug;

use crate::proto::ProtoError;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::Proof;
use crate::proto::op::{DnsResponse, Query, ResponseCode};
use crate::proto::rr::RData;
use crate::proto::rr::{Record, RecordType, rdata::SOA, resource::RecordRef};

/// The error type for network protocol errors (UDP, TCP, QUIC, H2, H3)
#[non_exhaustive]
#[derive(Error, Clone, Debug)]
pub enum NetError {
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

    /// Unable to decode HTTP header value to string
    #[cfg(any(feature = "__https", feature = "__h3"))]
    #[error("header decode error: {0}")]
    Decode(Arc<ToStrError>),

    /// Semantic DNS errors
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// An HTTP/2 related error
    #[error("H2 error: {0}")]
    #[cfg(feature = "__https")]
    H2(Arc<h2::Error>),

    /// An HTTP/3 related error
    #[error("H3 error: {0}")]
    #[cfg(feature = "__h3")]
    H3(Arc<h3::error::StreamError>),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Unable to parse header value as number
    #[error("unable to parse number: {0}")]
    ParseInt(#[from] ParseIntError),

    /// No connections available
    #[error("no connections available")]
    NoConnections,

    /// Protocol error from higher layers
    #[error("protocol error: {0}")]
    Proto(#[from] ProtoError),

    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(Arc<io::Error>),

    /// A request timed out
    #[error("request timed out")]
    Timeout,

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

impl NetError {
    /// Returns true if the domain does not exist
    #[inline]
    pub fn is_nx_domain(&self) -> bool {
        matches!(
            self,
            Self::Dns(DnsError::NoRecordsFound(NoRecords {
                response_code: ResponseCode::NXDomain,
                ..
            }))
        )
    }

    /// Returns true if the error represents NoRecordsFound
    #[inline]
    pub fn is_no_records_found(&self) -> bool {
        matches!(self, Self::Dns(DnsError::NoRecordsFound { .. }))
    }

    /// Returns the SOA record, if the error contains one
    #[inline]
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self {
            Self::Dns(DnsError::NoRecordsFound(NoRecords { soa, .. })) => soa,
            _ => None,
        }
    }
}

impl From<NoRecords> for NetError {
    fn from(no_records: NoRecords) -> Self {
        Self::Dns(DnsError::NoRecordsFound(no_records))
    }
}

#[cfg(feature = "__h3")]
impl From<h3::error::StreamError> for NetError {
    fn from(e: h3::error::StreamError) -> Self {
        Self::H3(Arc::new(e))
    }
}

#[cfg(feature = "__https")]
impl From<h2::Error> for NetError {
    fn from(e: h2::Error) -> Self {
        Self::H2(Arc::new(e))
    }
}

#[cfg(any(feature = "__https", feature = "__h3"))]
impl From<ToStrError> for NetError {
    fn from(e: ToStrError) -> Self {
        Self::Decode(Arc::new(e))
    }
}

impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(Arc::new(e)),
        }
    }
}

impl From<String> for NetError {
    fn from(msg: String) -> Self {
        Self::Msg(msg)
    }
}

impl From<&'static str> for NetError {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg)
    }
}

/// Semantic DNS errors
#[derive(Clone, Debug, Error)]
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
                                if let RData::NS(ns_data) = ns.data() {
                                    if *record.name() == **ns_data && matches!(record.data(), RData::A(_) | RData::AAAA(_)) {
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
