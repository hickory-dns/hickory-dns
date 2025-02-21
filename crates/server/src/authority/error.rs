// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, sync::Arc};

use enum_as_inner::EnumAsInner;
use thiserror::Error;

use crate::proto::op::ResponseCode;
use crate::proto::rr::{Record, rdata::SOA};
use crate::proto::{ProtoError, ProtoErrorKind};
#[cfg(feature = "recursor")]
use crate::recursor::ErrorKind;
#[cfg(feature = "resolver")]
use crate::resolver::ResolveError;

// TODO: should this implement Failure?
#[allow(clippy::large_enum_variant)]
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
    /// Resolve Error
    #[cfg(feature = "resolver")]
    #[error("Forward resolution error: {0}")]
    ResolveError(#[from] ResolveError),
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
            Self::ResponseCode(ResponseCode::NXDomain) => true,
            #[cfg(feature = "resolver")]
            Self::ResolveError(e) if e.is_nx_domain() => true,
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) if e.is_nx_domain() => true,
            _ => false,
        }
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        match self {
            #[cfg(feature = "resolver")]
            Self::ResolveError(e) if e.is_no_records_found() => true,
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) if e.is_no_records_found() => true,
            _ => false,
        }
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self {
            #[cfg(feature = "resolver")]
            Self::ResolveError(e) => e.into_soa(),
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) => e.into_soa(),
            _ => None,
        }
    }

    /// Return authority records
    pub fn authorities(&self) -> Option<Arc<[Record]>> {
        match self {
            Self::ProtoError(e) => match e.kind() {
                ProtoErrorKind::NoRecordsFound { authorities, .. } => authorities.clone(),
                _ => None,
            },
            #[cfg(feature = "recursor")]
            Self::RecursiveError(e) => match e.kind() {
                ErrorKind::Forward(fwd) => fwd.authorities.clone(),
                ErrorKind::Proto(proto) => match proto.kind() {
                    ProtoErrorKind::NoRecordsFound { authorities, .. } => authorities.clone(),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    /// This is a non-existent domain name
    pub fn is_refused(&self) -> bool {
        matches!(*self, Self::ResponseCode(ResponseCode::Refused))
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
        Self::new(io::ErrorKind::Other, Box::new(e))
    }
}
