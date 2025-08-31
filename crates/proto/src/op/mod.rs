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

mod edns;
pub use edns::{Edns, EdnsFlags};

pub mod header;
pub use header::{Header, MessageType};

mod lower_query;
pub use lower_query::LowerQuery;

pub mod message;
pub use message::{Message, MessageParts, MessageSignature, MessageSigner, MessageVerifier};

pub mod op_code;
pub use op_code::OpCode;

pub mod query;
pub use query::Query;

pub mod response_code;
pub use response_code::ResponseCode;

pub mod update_message;
pub use update_message::UpdateMessage;
