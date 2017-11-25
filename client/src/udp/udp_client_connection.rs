// Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
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

//! UDP based DNS client connection for Client impls

use std::io;
use std::net::SocketAddr;

use futures::Future;
use tokio_core::reactor::Handle;
use trust_dns_proto::DnsStreamHandle;

use error::*;
use client::ClientConnection;
use udp::UdpClientStream;

/// UDP based DNS Client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct UdpClientConnection {
    name_server: SocketAddr,
}

impl UdpClientConnection {
    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of binding the socket to 0.0.0.0 and starting the listening
    ///        event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
        Ok(UdpClientConnection { name_server })
    }
}

impl ClientConnection for UdpClientConnection {
    type MessageStream = UdpClientStream;

    fn new_stream(
        &self,
        handle: &Handle,
    ) -> ClientResult<
        (
            Box<Future<Item = Self::MessageStream, Error = io::Error>>,
            Box<DnsStreamHandle<Error = ClientError>>,
        ),
    > {
        let (udp_client_stream, handle) = UdpClientStream::new(self.name_server, handle);

        Ok((udp_client_stream, handle))
    }
}
