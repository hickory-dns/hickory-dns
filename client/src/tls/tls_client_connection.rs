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
#[cfg(target_os = "linux")]
use openssl::x509::X509 as OpensslX509;
#[cfg(target_os = "macos")]
use security_framework::certificate::SecCertificate;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;

use ::error::*;
use ::client::{ClientConnection, ClientStreamHandle};
use ::tls::{TlsClientStream, TlsClientStreamBuilder};

/// TCP based DNS client
pub struct TlsClientConnection {
  io_loop: Core,
  tls_client_stream: Box<Future<Item=TlsClientStream, Error=io::Error>>,
  client_stream_handle: Box<ClientStreamHandle>,
}

impl TlsClientConnection {
  pub fn builder() -> TlsClientConnectionBuilder {
    TlsClientConnectionBuilder(TlsClientStream::builder())
  }
}

impl ClientConnection for TlsClientConnection {
  type MessageStream = TlsClientStream;

  fn unwrap(self) -> (Core, Box<Future<Item=Self::MessageStream, Error=io::Error>>, Box<ClientStreamHandle>) {
    (self.io_loop, self.tls_client_stream, self.client_stream_handle)
  }
}

pub struct TlsClientConnectionBuilder(TlsClientStreamBuilder);

impl TlsClientConnectionBuilder {
  #[cfg(target_os = "macos")]
  pub fn add_ca(&mut self, ca: SecCertificate) {
    self.0.add_ca(ca);
  }

  #[cfg(target_os = "linux")]
  pub fn add_ca(&mut self, ca: OpensslX509) {
    self.0.add_ca(ca);
  }

  /// Client side identity for client auth in TLS (aka mutual TLS auth)
  pub fn identity(&mut self, pkcs12: Pkcs12) {
    self.0.identity(pkcs12);
  }

  /// Creates a new client connection.
  ///
  /// *Note* this has side affects of establishing the connection to the specified DNS server and
  ///        starting the event_loop. Expect this to change in the future.
  ///
  /// # Arguments
  ///
  /// * `name_server` - address of the name server to use for queries
  pub fn build(self, name_server: SocketAddr, subject_name: String) -> ClientResult<TlsClientConnection> {
    let io_loop = try!(Core::new());
    let (tls_client_stream, handle) = self.0.build(name_server, subject_name, io_loop.handle());

    Ok(TlsClientConnection{ io_loop: io_loop, tls_client_stream: tls_client_stream, client_stream_handle: handle })
  }
}
