// Copyright (C) 2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trait for client connections

use std::io;

use futures::Future;
use tokio_core::reactor::Handle;

use trust_dns_proto::DnsStreamHandle;

use error::*;

/// Trait for client connections
pub trait ClientConnection: Sized {
    /// The associated DNS Message stream type.
    type MessageStream;

    /// Return the inner Futures items
    ///
    /// Consumes the connection and allows for future based operations afterward.
    fn new_stream(
        &self,
        handle: &Handle,
    ) -> ClientResult<
        (
            Box<Future<Item = Self::MessageStream, Error = io::Error>>,
            Box<DnsStreamHandle<Error = ClientError>>,
        ),
    >;
}
