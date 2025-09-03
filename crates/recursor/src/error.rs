// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use std::{fmt, io, sync::Arc};

use enum_as_inner::EnumAsInner;
use hickory_proto::op::Query;
use thiserror::Error;
use tracing::warn;

use crate::proto::{
    DnsError, ForwardNSData, ProtoErrorKind,
    op::ResponseCode,
    rr::{Name, Record, RecordType, rdata::SOA},
    {NoRecords, ProtoError},
};
#[cfg(feature = "backtrace")]
use crate::proto::{ExtBacktrace, trace};

/// The error kind for errors that get returned in the crate
#[derive(Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum ErrorKind {
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

    /// Upstream DNS authority returned an empty RRset
    #[error("negative response")]
    Negative(AuthorityData),

    /// Upstream DNS authority returned a referral to another set of nameservers in the form of
    /// additional NS records.
    #[error("forward NS Response")]
    ForwardNS(Arc<[ForwardNSData]>),

    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(ProtoError),

    /// A request timed out
    #[error("request timed out")]
    Timeout,

    /// Could not fetch all records because a recursion limit was exceeded
    #[error("maximum recursion limit exceeded: {count} queries")]
    RecursionLimitExceeded {
        /// Number of queries that were made
        count: usize,
    },
}

/// The error type for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub struct Error {
    /// Kind of error that occurred
    pub kind: ErrorKind,
    /// Backtrace to the source of the error
    #[cfg(feature = "backtrace")]
    pub backtrack: Option<ExtBacktrace>,
}

impl Error {
    /// Get the kind of the error
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Take kind from the Error
    pub fn into_kind(self) -> ErrorKind {
        self.kind
    }

    /// Returns true if the domain does not exist
    pub fn is_nx_domain(&self) -> bool {
        match &self.kind {
            ErrorKind::Proto(proto) => proto.is_nx_domain(),
            ErrorKind::Negative(fwd) => fwd.is_nx_domain(),
            _ => false,
        }
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        match &self.kind {
            ErrorKind::Proto(proto) => proto.is_no_records_found(),
            ErrorKind::Negative(fwd) => fwd.is_no_records_found(),
            _ => false,
        }
    }

    /// Returns true if a query timed out
    pub fn is_timeout(&self) -> bool {
        let proto_error = match &self.kind {
            ErrorKind::Proto(proto) => proto,
            _ => return false,
        };
        matches!(proto_error.kind(), ProtoErrorKind::Timeout)
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self.kind {
            ErrorKind::Proto(proto) => proto.into_soa(),
            ErrorKind::Negative(fwd) => fwd.soa,
            _ => None,
        }
    }

    /// Return additional records
    pub fn authorities(self) -> Option<Arc<[Record]>> {
        match self.kind {
            ErrorKind::Negative(fwd) => fwd.authorities,
            _ => None,
        }
    }

    /// Test if the recursion depth has been exceeded, and return an error if it has.
    pub fn recursion_exceeded(limit: Option<u8>, depth: u8, name: &Name) -> Result<(), Error> {
        match limit {
            Some(limit) if depth > limit => {}
            _ => return Ok(()),
        }

        warn!("recursion depth exceeded for {name}");
        Err(ErrorKind::RecursionLimitExceeded {
            count: depth as usize,
        }
        .into())
    }
}

impl fmt::Display for Error {
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

impl<E> From<E> for Error
where
    E: Into<ErrorKind>,
{
    fn from(error: E) -> Self {
        Self {
            kind: error.into(),
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Self {
        ErrorKind::Message(msg).into()
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        ErrorKind::Msg(msg).into()
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e.kind() {
            ErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::other(e),
        }
    }
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Self {
        let no_records = match e.kind() {
            ProtoErrorKind::Dns(DnsError::NoRecordsFound(no_records)) => no_records,
            _ => return ErrorKind::Proto(e).into(),
        };

        if let Some(ns) = &no_records.ns {
            ErrorKind::ForwardNS(ns.clone())
        } else {
            ErrorKind::Negative(AuthorityData::new(
                no_records.query.clone(),
                no_records.soa.clone(),
                true,
                matches!(no_records.response_code, ResponseCode::NXDomain),
                no_records.authorities.clone(),
            ))
        }
        .into()
    }
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match self {
            MaxRecordLimitExceeded { count, record_type } => MaxRecordLimitExceeded {
                count: *count,
                record_type: *record_type,
            },
            Message(msg) => Message(msg),
            Msg(msg) => Msg(msg.clone()),
            Negative(ns) => Negative(ns.clone()),
            ForwardNS(ns) => ForwardNS(ns.clone()),
            Io(io) => Io(std::io::Error::from(io.kind())),
            Proto(proto) => Proto(proto.clone()),
            Timeout => Self::Timeout,
            RecursionLimitExceeded { count } => RecursionLimitExceeded { count: *count },
        }
    }
}

impl From<Error> for ProtoError {
    fn from(e: Error) -> Self {
        match e.kind {
            ErrorKind::Negative(fwd) => DnsError::NoRecordsFound(fwd.into()).into(),
            _ => ProtoError::from(e.to_string()),
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

impl From<AuthorityData> for NoRecords {
    fn from(data: AuthorityData) -> NoRecords {
        let response_code = match data.is_nx_domain() {
            true => ResponseCode::NXDomain,
            false => ResponseCode::NoError,
        };

        let mut new = NoRecords::new(data.query, response_code);
        new.soa = data.soa;
        new.authorities = data.authorities;
        new
    }
}
