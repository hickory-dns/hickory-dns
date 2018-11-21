/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
mod authority;
mod catalog;
pub(crate) mod message_request;
mod message_response;

pub use self::auth_lookup::AuthLookup;
pub use self::authority::Authority;
pub use self::catalog::Catalog;
pub use self::message_request::{MessageRequest, Queries, UpdateRequest};
pub use self::message_response::{MessageResponse, MessageResponseBuilder};
