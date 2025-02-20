// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Module for `Catalog` of `Authority` zones which are responsible for storing `RRSet` records.

use crate::proto::op::ResponseCode;

/// Result of an Update operation
pub type UpdateResult<T> = Result<T, ResponseCode>;

mod auth_lookup;
#[allow(clippy::module_inception)]
mod authority;
pub(crate) mod authority_object;
mod catalog;
mod error;
pub(crate) mod message_request;
mod message_response;
mod zone_type;

pub use self::auth_lookup::{
    AnyRecords, AuthLookup, AuthLookupIter, LookupRecords, LookupRecordsIter,
};
pub use self::authority::{Authority, LookupControlFlow, LookupOptions};
pub use self::authority_object::{AuthorityObject, DnssecSummary, EmptyLookup, LookupObject};
pub use self::catalog::Catalog;
pub use self::error::LookupError;
pub use self::message_request::{MessageRequest, Queries, UpdateRequest};
pub use self::message_response::{MessageResponse, MessageResponseBuilder};
pub use self::zone_type::ZoneType;

#[cfg(feature = "__dnssec")]
pub use self::authority::{DnssecAuthority, Nsec3QueryInfo};
