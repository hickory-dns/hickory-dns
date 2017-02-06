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

//! TCP based DNS client

use std::net::SocketAddr;
use std::io;

use futures::Future;
use native_tls::Pkcs12;
use security_framework::certificate::SecCertificate;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;

use ::error::*;
use ::client::{ClientConnection, ClientStreamHandle};
use ::tls::TlsClientStream;

/// TCP based DNS client
pub struct TlsClientConnection {
  io_loop: Core,
  tls_client_stream: Box<Future<Item=TlsClientStream, Error=io::Error>>,
  client_stream_handle: Box<ClientStreamHandle>,
}

impl TlsClientConnection {
  /// Creates a new client connection.
  ///
  /// *Note* this has side affects of establishing the connection to the specified DNS server and
  ///        starting the event_loop. Expect this to change in the future.
  ///
  /// # Arguments
  ///
  /// * `name_server` - address of the name server to use for queries
  pub fn new(name_server: SocketAddr,
             subject_name: String,
             certs: Vec<SecCertificate>,
             pkcs12: Option<Pkcs12>) -> ClientResult<Self> {
    let io_loop = try!(Core::new());
    let (tls_client_stream, handle) = TlsClientStream::new_tls(name_server, subject_name, io_loop.handle(), certs, pkcs12);

    Ok(TlsClientConnection{ io_loop: io_loop, tls_client_stream: tls_client_stream, client_stream_handle: handle })
  }
}

impl ClientConnection for TlsClientConnection {
  type MessageStream = TlsClientStream;

  fn unwrap(self) -> (Core, Box<Future<Item=Self::MessageStream, Error=io::Error>>, Box<ClientStreamHandle>) {
    (self.io_loop, self.tls_client_stream, self.client_stream_handle)
  }
}
