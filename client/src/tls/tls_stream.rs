// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::io;

use futures::Future;
use futures::sync::mpsc::unbounded;
use native_tls::TlsConnector;
use native_tls::backend::security_framework::TlsConnectorBuilderExt;
use security_framework::certificate::SecCertificate;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::{Handle};
use tokio_tls::{TlsConnectorExt, TlsStream as TokioTlsStream};

use ::BufStreamHandle;
use ::tcp::TcpStream;

pub type TlsStream = TcpStream<TokioTlsStream<TokioTcpStream>>;

impl TlsStream {
  /// Creates a new TlsStream to the specified name_server
  ///
  /// [RFC 7858](https://tools.ietf.org/html/rfc7858), DNS over TLS, May 2016
  ///
  /// ```text
  /// 3.2.  TLS Handshake and Authentication
  ///
  ///   Once the DNS client succeeds in connecting via TCP on the well-known
  ///   port for DNS over TLS, it proceeds with the TLS handshake [RFC5246],
  ///   following the best practices specified in [BCP195].
  ///
  ///   The client will then authenticate the server, if required.  This
  ///   document does not propose new ideas for authentication.  Depending on
  ///   the privacy profile in use (Section 4), the DNS client may choose not
  ///   to require authentication of the server, or it may make use of a
  ///   trusted Subject Public Key Info (SPKI) Fingerprint pin set.
  ///
  ///   After TLS negotiation completes, the connection will be encrypted and
  ///   is now protected from eavesdropping.
  /// ```
  ///
  /// # Arguments
  ///
  /// * `name_server` - IP and Port for the remote DNS resolver
  /// * `name` - The Subject Public Key Info (SPKI) name as associated to a certificate
  /// * `loop_handle` - The reactor Core handle
  /// TODO: make a builder for the certifiates...
  pub fn new_tls(name_server: SocketAddr, name: String, loop_handle: Handle, certs: Vec<SecCertificate>) -> (Box<Future<Item=TlsStream, Error=io::Error>>, BufStreamHandle) {
    let (message_sender, outbound_messages) = unbounded();
    let tcp = TokioTcpStream::connect(&name_server, &loop_handle);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream: Box<Future<Item=TlsStream, Error=io::Error>> = Box::new(
      tcp
      .and_then(move |tcp_stream| {
        let mut builder = TlsConnector::builder().unwrap(); // FIXME: remove unwrap()
        builder.anchor_certificates(&certs);
        let connector = builder.build().unwrap(); // FIXME: remove unwrap()
        connector.connect_async(&name, tcp_stream)
                 .map(move |tls_stream| {
                   TcpStream::from_stream_with_receiver(tls_stream, name_server, outbound_messages)
                 })
                 .map_err(move |e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {}", e)))
      })
      .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tls error: {}", e)))
    );

    (stream, message_sender)
  }

  /// Initializes a TcpStream with an existing tokio_core::net::TcpStream.
  ///
  /// This is intended for use with a TcpListener and Incoming.
  pub fn from_tls_stream(stream: TokioTlsStream<TokioTcpStream>, peer_addr: SocketAddr) -> (Self, BufStreamHandle) {
    let (message_sender, outbound_messages) = unbounded();

    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);

    (stream, message_sender)
  }
}

#[cfg(test)] use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a mesage buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
#[test]
fn test_tls_client_stream_ipv4() {
  tls_client_stream_test(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_tcp_client_stream_ipv6() {
  tls_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

#[cfg(test)]
const TEST_BYTES: &'static [u8; 8] = b"DEADBEEF";
#[cfg(test)]
const TEST_BYTES_LEN: usize = 8;

#[cfg(test)]
fn tls_client_stream_test(server_addr: IpAddr) {
  use std::io::{Read, Write};
  use futures::Stream;
  use tokio_core::reactor::Core;
  use native_tls;
  use native_tls::TlsAcceptor;
  use openssl::hash::MessageDigest;
  use openssl::pkcs12::*;
  use openssl::pkey::*;
  use openssl::rsa::*;
  use openssl::x509::*;
  use openssl::x509::extension::*;

  use std;
  let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let succeeded_clone = succeeded.clone();
  std::thread::Builder::new().name("thread_killer".to_string()).spawn(move || {
    let succeeded = succeeded_clone.clone();
    for _ in 0..15 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      if succeeded.load(std::sync::atomic::Ordering::Relaxed) { return }
    }

    panic!("timeout");
  }).unwrap();

  // Generate X509 certificate
  let subject_name = "ns.example.com";
  let rsa = Rsa::generate(2048).unwrap();
  let pkey = PKey::from_rsa(rsa).unwrap();

  let gen = X509Generator::new()
                         .set_valid_period(365*2)
                         .add_name("CN".to_owned(), subject_name.to_string())
                         .set_sign_hash(MessageDigest::sha256())
                         .add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature]));

  let cert = gen.sign(&pkey).unwrap();
  let cert_der = cert.to_der().unwrap();

  let pkcs12_builder = Pkcs12::builder("mypassword", subject_name, &pkey, &cert);
  let pkcs12 = pkcs12_builder.build().unwrap();
  let pkcs12_der = pkcs12.to_der().unwrap();

  //let pkey_der = pkey.private_key_to_der().unwrap();

  // TODO: need a timeout on listen
  let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
  let server_addr = server.local_addr().unwrap();

  let send_recv_times = 4;

  // an in and out server
  let server_pkcs12_der = pkcs12_der.clone();
  let server_handle = std::thread::Builder::new().name("test_tls_client_stream:server".to_string()).spawn(move || {

    let pkcs12 = native_tls::Pkcs12::from_der(&server_pkcs12_der, "mypassword").expect("Pkcs12::from_der");
    let tls = TlsAcceptor::builder(pkcs12).unwrap().build().unwrap();

    let (socket, _) = server.accept().expect("accept failed");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
    socket.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...

    let mut socket = tls.accept(socket).unwrap();

    for _ in 0..send_recv_times {
      // wait for some bytes...
      let mut len_bytes = [0_u8; 2];
      socket.read_exact(&mut len_bytes).expect("SERVER: receive failed");
      let length = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;
      assert_eq!(length as usize, TEST_BYTES_LEN);

      let mut buffer = [0_u8; TEST_BYTES_LEN];
      socket.read_exact(&mut buffer).unwrap();

      // println!("read bytes iter: {}", i);
      assert_eq!(&buffer, TEST_BYTES);

      // bounce them right back...
      socket.write_all(&len_bytes).expect("SERVER: send length failed");
      socket.write_all(&buffer).expect("SERVER: send buffer failed");
      // println!("wrote bytes iter: {}", i);
      std::thread::yield_now();
    }
  }).unwrap();

  // setup the client, which is going to run on the testing thread...
  let mut io_loop = Core::new().unwrap();

  // the tests should run within 5 seconds... right?
  // TODO: add timeout here, so that test never hangs...
  // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());
  let trust_chain = SecCertificate::from_der(&cert_der).unwrap();
  let (stream, sender) = TlsStream::new_tls(server_addr, subject_name.to_string(), io_loop.handle(), vec![trust_chain]);

  let mut stream = io_loop.run(stream).ok().expect("run failed to get stream");

  for _ in 0..send_recv_times {
    // test once
    sender.send((TEST_BYTES.to_vec(), server_addr)).expect("send failed");
    let (buffer, stream_tmp) = io_loop.run(stream.into_future()).ok().expect("future iteration run failed");
    stream = stream_tmp;
    let (buffer, _) = buffer.expect("no buffer received");
    assert_eq!(&buffer, TEST_BYTES);
  }

  succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
  server_handle.join().expect("server thread failed");
}
