// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt;

use trust_dns::op::ResponseCode;

/// A query could not be fullfilled
#[derive(Debug, Eq, PartialEq)]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    NameExists,
    /// There was an error performing the lookup
    ResponseCode(ResponseCode),
}

impl LookupError {
    /// Create a lookup error, speicifying that a name exists at the location, but no matching RecordType
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

    /// This is a non-existant domain name
    pub fn is_nx_domain(&self) -> bool {
        match *self {
            LookupError::ResponseCode(ResponseCode::NXDomain) => true,
            _ => false,
        }
    }

    /// This is a non-existant domain name
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
            LookupError::ResponseCode(rc) => write!(f, "{}", rc),
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

pub type LookupResult<T> = Result<T, LookupError>;
