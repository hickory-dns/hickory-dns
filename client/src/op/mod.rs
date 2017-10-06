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

pub use trust_dns_proto::op::{Edns, Header, Message, MessageType, UpdateMessage, OpCode, Query,
                              ResponseCode};
