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

//! UDP based DNS client

use std::io;
use std::mem;
use std::net::{SocketAddr, ToSocketAddrs};
use std::fmt;

use futures::Future;
use futures::stream::Stream;
use rand::Rng;
use rand;
use tokio_core::reactor::Core;

use ::error::*;
use ::client::{ClientConnection, ClientStreamHandle};
use ::udp::UdpClientStream;

/// UDP based DNS client
pub struct UdpClientConnection {
  io_loop: Core,
  udp_client_stream: Box<Future<Item=UdpClientStream, Error=io::Error>>,
  client_stream_handle: Box<ClientStreamHandle>,
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
    let io_loop = try!(Core::new());
    let (udp_client_stream, handle) = UdpClientStream::new(name_server, io_loop.handle());

    Ok(UdpClientConnection{ io_loop: io_loop, udp_client_stream: udp_client_stream, client_stream_handle: handle })
  }
}

impl ClientConnection for UdpClientConnection {
  type MessageStream = UdpClientStream;

  fn unwrap(self) -> (Core, Box<Future<Item=Self::MessageStream, Error=io::Error>>, Box<ClientStreamHandle>) {
    (self.io_loop, self.udp_client_stream, self.client_stream_handle)
  }
}
