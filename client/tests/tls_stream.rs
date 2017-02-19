// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate futures;
extern crate native_tls;
extern crate openssl;
#[cfg(target_os = "macos")]
extern crate security_framework;
extern crate tokio_core;
extern crate trust_dns;
extern crate tokio_tls;

use std::{thread, time};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::io;
use std::fs::File;
use std::io::{Read, Write};

use futures::{future, Future, IntoFuture};
use futures::sync::mpsc::unbounded;
use native_tls::TlsConnector;
#[cfg(target_os = "macos")]
use native_tls::backend::security_framework::TlsConnectorBuilderExt;
#[cfg(target_os = "macos")]
use security_framework::certificate::SecCertificate;
#[cfg(target_os = "linux")]
use native_tls::backend::openssl::*;
use openssl::x509::*;
#[cfg(target_os = "linux")]
use openssl::x509::store::X509StoreBuilder;
use openssl::pkey::*;
use native_tls::Protocol::Tlsv12;
use tokio_core::net::TcpStream as TokioTcpStream;
use tokio_core::reactor::{Handle};
use tokio_tls::{TlsConnectorExt, TlsStream as TokioTlsStream};

use futures::Stream;
use tokio_core::reactor::Core;
use native_tls::TlsAcceptor;
use openssl::hash::MessageDigest;
use openssl::nid;
use openssl::pkcs12::*;
use openssl::pkey::*;
use openssl::rsa::*;
use openssl::x509::extension::*;
use openssl::ssl::{SSL_VERIFY_PEER, SSL_VERIFY_NONE, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};

use trust_dns::BufStreamHandle;
use trust_dns::tcp::TcpStream;
use trust_dns::tls::TlsStream;

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

const TEST_BYTES: &'static [u8; 8] = b"DEADBEEF";
const TEST_BYTES_LEN: usize = 8;

fn root_ca() -> (PKey, X509Name, X509) {
  let subject_name = "root.example.com";
  let rsa = Rsa::generate(2048).unwrap();
  let pkey = PKey::from_rsa(rsa).unwrap();

  let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
  x509_name.append_entry_by_text("CN", subject_name).unwrap();
  let x509_name = x509_name.build();

  let mut x509_build = openssl::x509::X509::builder().unwrap();
  x509_build.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
  x509_build.set_not_after(&openssl::asn1::Asn1Time::days_from_now(2).unwrap()).unwrap();
  x509_build.set_issuer_name(&x509_name).unwrap();
  x509_build.set_subject_name(&x509_name).unwrap();
  x509_build.set_pubkey(&pkey).unwrap();
  x509_build.append_extension(openssl::x509::X509Extension::new(None, None, "keyUsage", "digitalSignature").unwrap()).unwrap();
  x509_build.append_extension(openssl::x509::X509Extension::new(None, None, "basicConstraints", "CA:TRUE").unwrap()).unwrap();
  x509_build.sign(&pkey, MessageDigest::sha256()).unwrap();

  (pkey, x509_name, x509_build.build())
}

fn tls_client_stream_test(server_addr: IpAddr) {
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

  let (root_pkey, root_name, root_cert) = root_ca();
  let root_cert_der = root_cert.to_der().unwrap();

  let mut file = File::create("target/root_cert.pem").unwrap();
  file.write(&root_cert.to_pem().unwrap());

  // Generate X509 certificate
  let subject_name = "ns.example.com";
  let rsa = Rsa::generate(2048).unwrap();
  let pkey = PKey::from_rsa(rsa).unwrap();

  // let gen = X509Generator::new()
  //                        .set_valid_period(365*2)
  //                        .add_name("CN".to_owned(), subject_name.to_string())
  //                        .add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature]));
  //                        .set_sign_hash(MessageDigest::sha256());

  let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
  x509_name.append_entry_by_text("CN", subject_name).unwrap();
  let x509_name = x509_name.build();

  let mut x509_build = openssl::x509::X509::builder().unwrap();
  x509_build.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
  x509_build.set_not_after(&openssl::asn1::Asn1Time::days_from_now(256).unwrap()).unwrap();
  x509_build.set_issuer_name(&root_name).unwrap();
  x509_build.set_subject_name(&x509_name).unwrap();
  x509_build.set_pubkey(&pkey).unwrap();
  x509_build.append_extension(openssl::x509::X509Extension::new(None, None, "keyUsage", "digitalSignature").unwrap()).unwrap();
  x509_build.append_extension(openssl::x509::X509Extension::new(None, None, "basicConstraints", "CA:FALSE").unwrap()).unwrap();
  x509_build.sign(&root_pkey, MessageDigest::sha256()).unwrap();

  let cert = x509_build.build();
  let cert_der = cert.to_der().unwrap();

  let mut pkcs12_builder = Pkcs12::builder();

  let mut stack = openssl::stack::Stack::new().unwrap();
  stack.push(openssl::x509::X509::from_der(&root_cert_der).unwrap()).unwrap();
  pkcs12_builder.ca(stack);
  let pkcs12 = pkcs12_builder.build("mypass", subject_name, &pkey, &cert).unwrap();

  let pkcs12_der = pkcs12.to_der().unwrap();

  //let pkey_der = pkey.private_key_to_der().unwrap();

  // TODO: need a timeout on listen
  let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
  let server_addr = server.local_addr().unwrap();

  let send_recv_times = 4;

  // an in and out server
  let server_pkcs12_der = pkcs12_der.clone();
  let server_cert_der = cert_der.clone();
  let server_handle = std::thread::Builder::new().name("test_tls_client_stream:server".to_string()).spawn(move || {
    let pkcs12 = native_tls::Pkcs12::from_der(&server_pkcs12_der, "mypass").expect("Pkcs12::from_der");
    let mut tls = TlsAcceptor::builder(pkcs12).expect("build with pkcs12 failed");

    #[cfg(target_os = "linux")]
    {
      let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
      x509_name.append_entry_by_text("CN", subject_name).unwrap();
      let x509_name = x509_name.build();

      let mut stack = openssl::stack::Stack::new().unwrap();
      stack.push(x509_name);

      let mut openssl_builder = tls.builder_mut();
      let mut openssl_ctx_builder = openssl_builder.builder_mut();
      let mut mode = openssl::ssl::SslVerifyMode::empty();
      let cert = X509::from_der(&server_cert_der).unwrap();
      // mode.insert(SSL_VERIFY_PEER);
      // mode.insert(SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
      // mode.insert(SSL_VERIFY_NONE);

      openssl_ctx_builder.set_verify(SSL_VERIFY_NONE);
      //openssl_ctx_builder.add_extra_chain_cert(cert).unwrap();
      openssl_ctx_builder.set_client_ca_list(stack);
      // openssl_ctx_builder.set_default_verify_paths().unwrap();
      // openssl_ctx_builder.cert_store_mut().set_default_paths().unwrap();
    }

    let tls = tls.build().expect("tls build failed");

    let (socket, _) = server.accept().expect("tcp accept failed");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...
    socket.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap(); // should recieve something within 5 seconds...

    let mut socket = tls.accept(socket).expect("tls accept failed");

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

  // let the server go first
  std::thread::yield_now();
  std::thread::sleep_ms(100);

  // setup the client, which is going to run on the testing thread...
  let mut io_loop = Core::new().unwrap();

  // the tests should run within 5 seconds... right?
  // TODO: add timeout here, so that test never hangs...
  // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());

  #[cfg(target_os = "macos")]
  let trust_chain = SecCertificate::from_der(&root_cert_der).unwrap();

  #[cfg(target_os = "linux")]
  let trust_chain = X509::from_der(&root_cert_der).unwrap();

  let mut builder = TlsStream::builder();
  builder.add_ca(trust_chain);
  let (stream, sender) = builder.build(server_addr, subject_name.to_string(), io_loop.handle());

  // TODO: there is a random failure here... a race with the server thread most likely...
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
