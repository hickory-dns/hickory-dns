// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error;
use std::fmt;
use std::io;

#[cfg(feature = "trust-dns-resolver")]
use failure::{Compat, Fail};

use trust_dns::op::ResponseCode;
#[cfg(feature = "trust-dns-resolver")]
use trust_dns_resolver::error::ResolveError;

// TODO: should this implement Failure?
/// A query could not be fulfilled
#[derive(Debug, EnumAsInner)]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    NameExists,
    /// There was an error performing the lookup
    ResponseCode(ResponseCode),
    /// Resolve Error
    #[cfg(feature = "trust-dns-resolver")]
    ResolveError(Compat<ResolveError>),
    /// An underlying IO error occurred
    Io(io::Error),
}

impl LookupError {
    /// Create a lookup error, specifying that a name exists at the location, but no matching RecordType
    pub fn for_name_exists() -> Self {
        LookupError::NameExists
    }

    /// True if other records exist at the same name, but not the searched for RecordType
    pub fn is_name_exists(&self) -> bool {
        match *self {
            LookupError::NameExists => true,
            _ => false,
        }
    }

    /// This is a non-existent domain name
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            LookupError::ResponseCode(ResponseCode::NXDomain) => true,
            _ => false,
        }
    }

    /// This is a non-existent domain name
    pub fn is_refused(&self) -> bool {
        match *self {
            LookupError::ResponseCode(ResponseCode::Refused) => true,
            _ => false,
        }
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupError::NameExists => write!(f, "NameExists"),
            LookupError::ResponseCode(rc) => write!(f, "response_code: {}", rc),
            #[cfg(feature = "trust-dns-resolver")]
            LookupError::ResolveError(e) => write!(f, "resolve_error: {}", e),
            LookupError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl error::Error for LookupError {
    fn description(&self) -> &str {
        match self {
            LookupError::NameExists => "record type not found at name, but others exist",
            LookupError::ResponseCode(_rc) => "an response code other than NoError returned",
            #[cfg(feature = "trust-dns-resolver")]
            LookupError::ResolveError(_e) => "the resolver encountered an error",
            LookupError::Io(_e) => "there was an underlying IO error during search",
        }
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LookupError::NameExists => None,
            LookupError::ResponseCode(_rc) => None,
            #[cfg(feature = "trust-dns-resolver")]
            LookupError::ResolveError(e) => e.source(),
            LookupError::Io(e) => e.source(),
        }
    }
}

impl From<ResponseCode> for LookupError {
    fn from(code: ResponseCode) -> Self {
        // this should never be a NoError
        debug_assert!(code != ResponseCode::NoError);
        LookupError::ResponseCode(code)
    }
}

#[cfg(feature = "trust-dns-resolver")]
impl From<ResolveError> for LookupError {
    fn from(e: ResolveError) -> Self {
        LookupError::ResolveError(e.compat())
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
