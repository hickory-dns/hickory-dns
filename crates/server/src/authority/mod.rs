// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Module for `Catalog` of `Authority` zones which are responsible for storing `RRSet` records.

use trust_dns::op::ResponseCode;

/// Result of an Update operation
pub type UpdateResult<T> = Result<T, ResponseCode>;

/// The type of zone stored in a Catalog
#[derive(Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
pub enum ZoneType {
    /// This authority for a zone, i.e. the Primary
    Master,
    /// A secondary, i.e. replicated from the Master
    Slave,
    /// A cached zone with recursive resolver abilities
    Hint,
    /// A cached zone where all requests are forwarded to another Resolver
    Forward,
}

mod auth_lookup;
#[allow(clippy::module_inception)]
mod authority;
pub(crate) mod authority_object;
mod catalog;
pub(crate) mod lookup_object;
pub(crate) mod message_request;
mod message_response;
mod result;

pub use self::auth_lookup::{
    AnyRecords, AuthLookup, AuthLookupIter, LookupRecords, LookupRecordsIter,
};
pub use self::authority::Authority;
pub use self::authority_object::AuthorityObject;
pub use self::catalog::Catalog;
pub use self::lookup_object::LookupObject;
pub use self::message_request::{MessageRequest, Queries, UpdateRequest};
pub use self::message_response::{MessageResponse, MessageResponseBuilder};
pub use self::result::{LookupError, LookupResult};
