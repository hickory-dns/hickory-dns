// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::io;

use futures::Future;
use native_tls::Pkcs12;
#[cfg(target_os = "linux")]
use openssl::x509::X509 as OpensslX509;
#[cfg(target_os = "macos")]
use security_framework::certificate::SecCertificate;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::{Handle};
use tokio_tls::TlsStream as TokioTlsStream;

use ::BufClientStreamHandle;
use ::tcp::TcpClientStream;
use ::tls::{TlsStream, TlsStreamBuilder};
use ::client::ClientStreamHandle;

pub type TlsClientStream = TcpClientStream<TokioTlsStream<TokioTcpStream>>;

impl TlsClientStream {
  pub fn builder() -> TlsClientStreamBuilder {
    TlsClientStreamBuilder(TlsStream::builder())
  }
}

pub struct TlsClientStreamBuilder(TlsStreamBuilder);

impl TlsClientStreamBuilder {
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

  pub fn build(self, name_server: SocketAddr, subject_name: String, loop_handle: Handle)
         -> (Box<Future<Item=TlsClientStream, Error=io::Error>>, Box<ClientStreamHandle>) {
    let (stream_future, sender) = self.0.build(name_server, subject_name, loop_handle);

    let new_future: Box<Future<Item=TlsClientStream, Error=io::Error>> =
      Box::new(stream_future.map(move |tls_stream| {
        TcpClientStream::from_stream(tls_stream)
      }));

    let sender = Box::new(BufClientStreamHandle{ name_server: name_server, sender: sender });

    (new_future, sender)
  }
}
