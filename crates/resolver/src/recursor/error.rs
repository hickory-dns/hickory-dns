// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use std::io;
use std::sync::Arc;

use thiserror::Error;
use tracing::warn;

use crate::{
    net::{DnsError, ForwardNSData, NetError, NoRecords},
    proto::{
        ProtoError,
        op::Query,
        op::ResponseCode,
        rr::{Name, Record, RecordType, rdata::SOA},
    },
};

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecursorError {
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
    Io(#[from] io::Error),

    /// An error got returned by the hickory-proto crate
    #[error("net error: {0}")]
    Net(NetError),

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

impl RecursorError {
    /// Test if the recursion depth has been exceeded, and return an error if it has.
    pub fn recursion_exceeded(limit: u8, depth: u8, name: &Name) -> Result<(), Self> {
        if depth < limit {
            return Ok(());
        }

        warn!("recursion depth exceeded for {name}");
        Err(Self::RecursionLimitExceeded {
            count: depth as usize,
        })
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self {
            Self::Net(net) => net.into_soa(),
            Self::Negative(fwd) => fwd.soa,
            _ => None,
        }
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        match self {
            Self::Net(net) => net.is_no_records_found(),
            Self::Negative(fwd) => fwd.is_no_records_found(),
            _ => false,
        }
    }

    /// Returns true if the domain does not exist
    pub fn is_nx_domain(&self) -> bool {
        match self {
            Self::Net(net) => net.is_nx_domain(),
            Self::Negative(fwd) => fwd.is_nx_domain(),
            _ => false,
        }
    }

    /// Returns true if a query timed out
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::Net(net) => matches!(net, NetError::Timeout),
            _ => false,
        }
    }
}

impl From<NetError> for RecursorError {
    fn from(e: NetError) -> Self {
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = e else {
            return Self::Net(e);
        };

        if let Some(ns) = no_records.ns {
            Self::ForwardNS(ns)
        } else {
            Self::Negative(AuthorityData::new(
                no_records.query,
                no_records.soa,
                true,
                matches!(no_records.response_code, ResponseCode::NXDomain),
                no_records.authorities,
            ))
        }
    }
}

impl From<RecursorError> for NetError {
    fn from(e: RecursorError) -> Self {
        match e {
            RecursorError::Negative(fwd) => DnsError::NoRecordsFound(fwd.into()).into(),
            _ => Self::from(e.to_string()),
        }
    }
}

impl From<ProtoError> for RecursorError {
    fn from(e: ProtoError) -> Self {
        NetError::from(e).into()
    }
}

impl From<String> for RecursorError {
    fn from(msg: String) -> Self {
        Self::Msg(msg)
    }
}

impl From<&'static str> for RecursorError {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg)
    }
}

impl Clone for RecursorError {
    fn clone(&self) -> Self {
        use self::RecursorError::*;
        match self {
            MaxRecordLimitExceeded { count, record_type } => MaxRecordLimitExceeded {
                count: *count,
                record_type: *record_type,
            },
            Message(msg) => Message(msg),
            Msg(msg) => Msg(msg.clone()),
            Negative(ns) => Negative(ns.clone()),
            ForwardNS(ns) => ForwardNS(ns.clone()),
            Io(io) => Io(io::Error::from(io.kind())),
            Net(net) => Net(net.clone()),
            Timeout => Self::Timeout,
            RecursionLimitExceeded { count } => RecursionLimitExceeded { count: *count },
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
    fn from(data: AuthorityData) -> Self {
        let response_code = match data.is_nx_domain() {
            true => ResponseCode::NXDomain,
            false => ResponseCode::NoError,
        };

        let mut new = Self::new(data.query, response_code);
        new.soa = data.soa;
        new.authorities = data.authorities;
        new
    }
}
