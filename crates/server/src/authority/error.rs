// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;

use enum_as_inner::EnumAsInner;
use thiserror::Error;

use crate::client::op::ResponseCode;
#[cfg(feature = "trust-dns-resolver")]
use crate::resolver::error::ResolveError;

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
    /// Resolve Error
    #[cfg(feature = "trust-dns-resolver")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
    #[error("Resolution error: {0}")]
    ResolveError(#[from] ResolveError),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(io::Error),
}

impl LookupError {
    /// Create a lookup error, specifying that a name exists at the location, but no matching RecordType
    pub fn for_name_exists() -> Self {
        LookupError::NameExists
    }

    /// True if other records exist at the same name, but not the searched for RecordType
    pub fn is_name_exists(&self) -> bool {
        matches!(*self, LookupError::NameExists)
    }

    /// This is a non-existent domain name
    pub fn is_nx_domain(&self) -> bool {
        matches!(*self, LookupError::ResponseCode(ResponseCode::NXDomain))
    }

    /// This is a non-existent domain name
    pub fn is_refused(&self) -> bool {
        matches!(*self, LookupError::ResponseCode(ResponseCode::Refused))
    }
}

impl From<ResponseCode> for LookupError {
    fn from(code: ResponseCode) -> Self {
        // this should never be a NoError
        debug_assert!(code != ResponseCode::NoError);
        LookupError::ResponseCode(code)
    }
}

impl From<io::Error> for LookupError {
    fn from(e: io::Error) -> Self {
        LookupError::Io(e)
    }
}

impl From<LookupError> for io::Error {
    fn from(e: LookupError) -> Self {
        io::Error::new(io::ErrorKind::Other, Box::new(e))
    }
}

/// Result of a Lookup in the Catalog and Authority
pub type LookupResult<T> = Result<T, LookupError>;
