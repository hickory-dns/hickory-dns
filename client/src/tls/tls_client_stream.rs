// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::io;

use futures::{Async, Future, Poll, Stream};
use native_tls::Pkcs12;
use security_framework::certificate::SecCertificate;
use tokio_core::io::Io;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::{Handle};
use tokio_tls::TlsStream as TokioTlsStream;

use ::BufClientStreamHandle;
use ::tcp::TcpClientStream;
use ::tls::TlsStream;
use ::client::ClientStreamHandle;

pub type TlsClientStream = TcpClientStream<TokioTlsStream<TokioTcpStream>>;

impl TlsClientStream {
  /// it is expected that the resolver wrapper will be responsible for creating and managing
  ///  new TcpClients such that each new client would have a random port (reduce chance of cache
  ///  poisoning)
  pub fn new_tls(name_server: SocketAddr,
                 subject_name: String,
                 loop_handle: Handle,
                 certs: Vec<SecCertificate>,
                 pkcs12: Option<Pkcs12>) -> (Box<Future<Item=TlsClientStream, Error=io::Error>>, Box<ClientStreamHandle>) {
    let (stream_future, sender) = TlsStream::new_tls(name_server, subject_name, loop_handle, certs, pkcs12);

    let new_future: Box<Future<Item=TlsClientStream, Error=io::Error>> =
      Box::new(stream_future.map(move |tls_stream| {
        TcpClientStream::from_stream(tls_stream)
      }));

    let sender = Box::new(BufClientStreamHandle{ name_server: name_server, sender: sender });

    (new_future, sender)
  }
}
