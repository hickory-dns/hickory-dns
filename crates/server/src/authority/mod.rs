// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Module for `Catalog` of `Authority` zones which are responsible for storing `RRSet` records.

use std::{io, sync::Arc};

use enum_as_inner::EnumAsInner;
use thiserror::Error;

#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::Proof;
use crate::proto::op::ResponseCode;
use crate::proto::rr::{Record, rdata::SOA};
use crate::proto::{NoRecords, ProtoError, ProtoErrorKind};
#[cfg(feature = "recursor")]
use crate::recursor::ErrorKind;

mod auth_lookup;
#[allow(clippy::module_inception)]
mod authority;
mod catalog;
pub(crate) mod message_request;
mod message_response;

pub use self::auth_lookup::{
    AnyRecords, AuthLookup, AuthLookupIter, LookupRecords, LookupRecordsIter,
};
pub use self::authority::{Authority, AxfrPolicy, LookupControlFlow, LookupOptions};
#[cfg(feature = "__dnssec")]
pub use self::authority::{DnssecAuthority, Nsec3QueryInfo};
pub use self::catalog::Catalog;
pub use self::message_request::{MessageRequest, Queries, UpdateRequest};
pub use self::message_response::{MessageResponse, MessageResponseBuilder};

/// Result of an Update operation
pub type UpdateResult<T> = Result<T, ResponseCode>;

/// A query could not be fulfilled
#[derive(Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    #[error("The name exists, but not for the record requested")]
    NameExists,
    /// There was an error performing the lookup
    #[error("Error performing lookup: {0}")]
    ResponseCode(ResponseCode),
    /// Proto error
    #[error("Proto error: {0}")]
    ProtoError(#[from] ProtoError),
    /// Recursive Resolver Error
    #[cfg(feature = "recursor")]
    #[error("Recursive resolution error: {0}")]
    RecursiveError(#[from] hickory_recursor::Error),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(io::Error),
}

impl LookupError {
    /// Create a lookup error, specifying that a name exists at the location, but no matching RecordType
    pub fn for_name_exists() -> Self {
        Self::NameExists
    }

    /// This is a non-existent domain name
    pub fn is_nx_domain(&self) -> bool {
        match self {
            Self::ProtoError(e) => e.is_nx_domain(),
            Self::ResponseCode(ResponseCode::NXDomain) => true,
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) if e.is_nx_domain() => true,
            _ => false,
        }
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        match self {
            Self::ProtoError(e) => e.is_no_records_found(),
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) if e.is_no_records_found() => true,
            _ => false,
        }
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self {
            Self::ProtoError(e) => e.into_soa(),
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) => e.into_soa(),
            _ => None,
        }
    }

    /// Return authority records
    pub fn authorities(&self) -> Option<Arc<[Record]>> {
        match self {
            Self::ProtoError(e) => match e.kind() {
                ProtoErrorKind::NoRecordsFound(NoRecords { authorities, .. }) => {
                    authorities.clone()
                }
                _ => None,
            },
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) => match e.kind() {
                ErrorKind::Negative(fwd) => fwd.authorities.clone(),
                ErrorKind::Proto(proto) => match proto.kind() {
                    ProtoErrorKind::NoRecordsFound(NoRecords { authorities, .. }) => {
                        authorities.clone()
                    }
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }
}

impl From<ResponseCode> for LookupError {
    fn from(code: ResponseCode) -> Self {
        // this should never be a NoError
        debug_assert!(code != ResponseCode::NoError);
        Self::ResponseCode(code)
    }
}

impl From<io::Error> for LookupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<LookupError> for io::Error {
    fn from(e: LookupError) -> Self {
        Self::other(Box::new(e))
    }
}

/// DNSSEC status of an answer
#[derive(Clone, Copy, Debug)]
pub enum DnssecSummary {
    /// All records have been DNSSEC validated
    Secure,
    /// At least one record is in the Bogus state
    Bogus,
    /// Insecure / Indeterminate (e.g. "Island of security")
    Insecure,
}

impl DnssecSummary {
    /// Whether the records have been DNSSEC validated or not
    #[cfg(feature = "__dnssec")]
    pub fn from_records<'a>(records: impl Iterator<Item = &'a Record>) -> Self {
        let mut all_secure = None;
        for record in records {
            match record.proof() {
                Proof::Secure => {
                    all_secure.get_or_insert(true);
                }
                Proof::Bogus => return Self::Bogus,
                _ => all_secure = Some(false),
            }
        }

        if all_secure.unwrap_or(false) {
            Self::Secure
        } else {
            Self::Insecure
        }
    }

    /// Whether the records have been DNSSEC validated or not
    #[cfg(not(feature = "__dnssec"))]
    fn from_records<'a>(_: impl Iterator<Item = &'a Record>) -> Self {
        Self::Insecure
    }
}

#[allow(deprecated)]
mod zone_type {
    use serde::{Deserialize, Serialize};

    /// The type of zone stored in a Catalog
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
    pub enum ZoneType {
        /// This authority for a zone
        Primary,
        /// A secondary, i.e. replicated from the Primary
        Secondary,
        /// A cached zone that queries other nameservers
        External,
    }

    impl ZoneType {
        /// Is this an authoritative Authority, i.e. it owns the records of the zone.
        pub fn is_authoritative(self) -> bool {
            matches!(self, Self::Primary | Self::Secondary)
        }
    }
}

pub use zone_type::ZoneType;
