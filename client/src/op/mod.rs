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

//! Operations to send with a `Client` or server, e.g. `Query`, `Message`, or `UpdateMessage` can
//! be used to gether to either query or update resource records sets.

use trust_dns_proto::edns;
use trust_dns_proto::header;
use trust_dns_proto::message;
use trust_dns_proto::op_code;
use trust_dns_proto::query;
use trust_dns_proto::response_code;

pub use edns::Edns;
pub use header::Header;
pub use header::MessageType;
pub use message::{Message, UpdateMessage};
pub use op_code::OpCode;
pub use query::Query;
pub use response_code::ResponseCode;
