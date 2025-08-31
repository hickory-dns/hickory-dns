/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Operations to send with a `Client` or server, e.g. `Query`, `Message`, or `UpdateMessage` can
//! be used together to either query or update resource records sets.

mod dns_request;
pub use dns_request::{DnsRequest, DnsRequestOptions};

mod dns_response;
pub use dns_response::DnsResponse;

mod edns;
pub use edns::{Edns, EdnsFlags};

mod header;
pub use header::{Header, MessageType};

mod lower_query;
pub use lower_query::LowerQuery;

mod message;
pub use message::{
    EmitAndCount, Message, MessageParts, MessageSignature, MessageSigner, MessageVerifier,
    ResponseSigner, emit_message_parts,
};

mod op_code;
pub use op_code::OpCode;

mod query;
pub use query::Query;

mod response_code;
pub use response_code::ResponseCode;

mod serial_message;
pub use serial_message::SerialMessage;

pub mod update_message;
pub use update_message::UpdateMessage;
