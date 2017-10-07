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

//! TCP based DNS client connection for Client impls

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use futures::Future;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use trust_dns_proto::DnsStreamHandle;

use error::*;
use client::{ClientConnection, ClientStreamHandle};
use tcp::TcpClientStream;

/// Tcp client connection
///
/// Use with `trust_dns::client::Client` impls
pub struct TcpClientConnection {
    io_loop: Core,
    tcp_client_stream: Box<Future<Item = TcpClientStream<TcpStream>, Error = io::Error>>,
    client_stream_handle: Box<DnsStreamHandle>,
}

impl TcpClientConnection {
    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// Default connection timeout is 5 seconds
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn new(name_server: SocketAddr) -> ClientResult<Self> {
        Self::with_timeout(name_server, Duration::from_secs(5))
    }

    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of establishing the connection to the specified DNS server and
    ///        starting the event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn with_timeout(name_server: SocketAddr, timeout: Duration) -> ClientResult<Self> {
        let io_loop = try!(Core::new());
        let (tcp_client_stream, handle) =
            TcpClientStream::<TcpStream>::with_timeout(name_server, &io_loop.handle(), timeout);

        Ok(TcpClientConnection {
            io_loop: io_loop,
            tcp_client_stream: tcp_client_stream,
            client_stream_handle: handle,
        })
    }
}

impl ClientConnection for TcpClientConnection {
    type MessageStream = TcpClientStream<TcpStream>;

    fn unwrap(
        self,
    ) -> (Core, Box<Future<Item = Self::MessageStream, Error = io::Error>>, Box<DnsStreamHandle>) {
        (
            self.io_loop,
            self.tcp_client_stream,
            self.client_stream_handle,
        )
    }
}
