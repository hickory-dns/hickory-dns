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

//! `Server` component for hosting a domain name servers operations.

mod request_stream;
mod server_future;
mod timeout_stream;
mod request_handler;
mod response_handler;

pub use self::request_stream::Request;
pub use self::request_stream::RequestStream;
pub use self::response_handler::{ResponseHandle, ResponseHandler};
pub use self::server_future::ServerFuture;
pub use self::timeout_stream::TimeoutStream;
pub use self::request_handler::RequestHandler;
