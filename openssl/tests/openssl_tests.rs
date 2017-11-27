// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_openssl;
extern crate trust_dns;
extern crate trust_dns_openssl;
extern crate trust_dns_proto;

use std::{thread, time};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(not(target_os = "linux"))]
use std::net::Ipv6Addr;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic;

use futures::Stream;
use openssl::pkey::*;
use openssl::ssl::*;
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use tokio_core::reactor::Core;

use openssl::asn1::*;
use openssl::bn::*;
use openssl::hash::MessageDigest;
use openssl::nid;
use openssl::pkcs12::*;
use openssl::rsa::*;
use openssl::x509::extension::*;

use trust_dns_openssl::TlsStreamBuilder;

// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a mesage buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
#[test]
fn test_tls_client_stream_ipv4() {
    tls_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), false)
}

// FIXME: mtls is disabled at the moment, it causes a hang on Linux, and is currently not supported on macOS
#[cfg(feature = "mtls")]
#[test]
#[cfg(not(target_os = "macos"))] // ignored until Travis-CI fixes IPv6
fn test_tls_client_stream_ipv4_mtls() {
    tls_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), true)
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_tls_client_stream_ipv6() {
    tls_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), false)
}

const TEST_BYTES: &'static [u8; 8] = b"DEADBEEF";
const TEST_BYTES_LEN: usize = 8;

#[allow(unused_mut)]
fn tls_client_stream_test(server_addr: IpAddr, mtls: bool) {
    let succeeded = Arc::new(atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
            for _ in 0..15 {
                thread::sleep(time::Duration::from_secs(1));
                if succeeded.load(atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let (root_pkey, root_name, root_cert) = root_ca();
    let root_cert_der = root_cert.to_der().unwrap();

    // Generate X509 certificate
    let subject_name = "ns.example.com";
    let (_ /*server_pkey*/, _ /*server_cert*/, pkcs12) =
        cert(subject_name, &root_pkey, &root_name, &root_cert);

    let server_pkcs12_der = pkcs12.to_der().unwrap();

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let send_recv_times = 4;

    // an in and out server
    let root_cert_der_copy = root_cert_der.clone();

    let server_handle = thread::Builder::new()
        .name("test_tls_client_stream:server".to_string())
        .spawn(move || {
            let pkcs12 = Pkcs12::from_der(&server_pkcs12_der)
                .and_then(|p| p.parse("mypass"))
                .expect("Pkcs12::from_der");
            let mut tls = SslAcceptorBuilder::mozilla_modern(
                SslMethod::tls(),
                &pkcs12.pkey,
                &pkcs12.cert,
                &pkcs12.chain,
            ).expect("mozilla_modern failed");

            {
                let mut openssl_ctx_builder = tls.builder_mut();

                let mut mode = SslVerifyMode::empty();

                // FIXME: mtls tests hang on Linux...
                if mtls {
                    mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

                    let mut store = X509StoreBuilder::new().unwrap();
                    let root_ca = X509::from_der(&root_cert_der_copy).unwrap();
                    store.add_cert(root_ca).unwrap();
                    openssl_ctx_builder
                        .set_verify_cert_store(store.build())
                        .unwrap();
                } else {
                    mode.insert(SSL_VERIFY_NONE);
                }

                openssl_ctx_builder.set_verify(mode);
            }

            // FIXME: add CA on macOS

            let tls = tls.build();

            // server_barrier.wait();
            let (socket, _) = server.accept().expect("tcp accept failed");
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should recieve something within 5 seconds...
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should recieve something within 5 seconds...

            let mut socket = tls.accept(socket).expect("tls accept failed");

            for _ in 0..send_recv_times {
                // wait for some bytes...
                let mut len_bytes = [0_u8; 2];
                socket
                    .read_exact(&mut len_bytes)
                    .expect("SERVER: receive failed");
                let length = (len_bytes[0] as u16) << 8 & 0xFF00 | len_bytes[1] as u16 & 0x00FF;
                assert_eq!(length as usize, TEST_BYTES_LEN);

                let mut buffer = [0_u8; TEST_BYTES_LEN];
                socket.read_exact(&mut buffer).unwrap();

                // println!("read bytes iter: {}", i);
                assert_eq!(&buffer, TEST_BYTES);

                // bounce them right back...
                socket
                    .write_all(&len_bytes)
                    .expect("SERVER: send length failed");
                socket
                    .write_all(&buffer)
                    .expect("SERVER: send buffer failed");
                // println!("wrote bytes iter: {}", i);
                std::thread::yield_now();
            }
        })
        .unwrap();

    // let the server go first
    std::thread::yield_now();

    // setup the client, which is going to run on the testing thread...
    let mut io_loop = Core::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());

    let trust_chain = X509::from_der(&root_cert_der).unwrap();


    // barrier.wait();
    let mut builder = TlsStreamBuilder::new();
    builder.add_ca(trust_chain);

    if mtls {
        config_mtls(&root_pkey, &root_name, &root_cert, &mut builder);
    }

    let (stream, sender) = builder.build(server_addr, subject_name.to_string(), &io_loop.handle());

    // TODO: there is a race failure here... a race with the server thread most likely...
    let mut stream = io_loop.run(stream).ok().expect("run failed to get stream");

    for _ in 0..send_recv_times {
        // test once
        sender
            .unbounded_send((TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = io_loop
            .run(stream.into_future())
            .ok()
            .expect("future iteration run failed");
        stream = stream_tmp;
        let (buffer, _) = buffer.expect("no buffer received");
        assert_eq!(&buffer, TEST_BYTES);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}

#[allow(unused_variables)]
fn config_mtls(
    root_pkey: &PKey,
    root_name: &X509Name,
    root_cert: &X509,
    builder: &mut TlsStreamBuilder,
) {
    #[cfg(feature = "mtls")]
    {
        // signed by the same root cert
        let client_name = "resolv.example.com";
        let (_ /*client_pkey*/, _ /*client_cert*/, client_identity) =
            cert(client_name, root_pkey, root_name, root_cert);

        let client_identity = Pkcs12::from_der(&client_identity)
            .and_then(|p| p.parse("mypass"))
            .expect("Pkcs12::from_der");
        let client_identity =
            Pkcs12::from_der(&client_identity.to_der().unwrap(), "mypass").unwrap();

        builder.identity(client_identity);
    }
}

/// Generates a root certificate
fn root_ca() -> (PKey, X509Name, X509) {
    let subject_name = "root.example.com";
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name
        .append_entry_by_nid(nid::COMMONNAME, subject_name)
        .unwrap();
    let x509_name = x509_name.build();

    let mut serial: BigNum = BigNum::new().unwrap();
    serial.pseudo_rand(32, MSB_MAYBE_ZERO, false).unwrap();
    let serial = serial.to_asn1_integer().unwrap();

    let mut x509_build = X509::builder().unwrap();
    x509_build
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509_build
        .set_not_after(&Asn1Time::days_from_now(256).unwrap())
        .unwrap();
    x509_build.set_issuer_name(&x509_name).unwrap();
    x509_build.set_subject_name(&x509_name).unwrap();
    x509_build.set_pubkey(&pkey).unwrap();
    x509_build.set_serial_number(&serial).unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    x509_build.append_extension(basic_constraints).unwrap();

    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("root.example.com")
        .build(&x509_build.x509v3_context(None, None))
        .unwrap();
    x509_build
        .append_extension(subject_alternative_name)
        .unwrap();

    x509_build.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = x509_build.build();

    (pkey, x509_name, cert)
}

/// Generates a certificate, see root_ca() for getting a root cert
fn cert(subject_name: &str, ca_pkey: &PKey, ca_name: &X509Name, _: &X509) -> (PKey, X509, Pkcs12) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name
        .append_entry_by_nid(nid::COMMONNAME, subject_name)
        .unwrap();
    let x509_name = x509_name.build();

    let mut serial: BigNum = BigNum::new().unwrap();
    serial.pseudo_rand(32, MSB_MAYBE_ZERO, false).unwrap();
    let serial = serial.to_asn1_integer().unwrap();

    let mut x509_build = X509::builder().unwrap();
    x509_build
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509_build
        .set_not_after(&Asn1Time::days_from_now(256).unwrap())
        .unwrap();
    x509_build.set_issuer_name(&ca_name).unwrap();
    x509_build.set_subject_name(&x509_name).unwrap();
    x509_build.set_pubkey(&pkey).unwrap();
    x509_build.set_serial_number(&serial).unwrap();

    let ext_key_usage = ExtendedKeyUsage::new().server_auth().build().unwrap();
    x509_build.append_extension(ext_key_usage).unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&x509_build.x509v3_context(None, None))
        .unwrap();
    x509_build.append_extension(subject_key_identifier).unwrap();

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&x509_build.x509v3_context(None, None))
        .unwrap();
    x509_build
        .append_extension(authority_key_identifier)
        .unwrap();

    // CA:FALSE
    let basic_constraints = BasicConstraints::new().critical().build().unwrap();
    x509_build.append_extension(basic_constraints).unwrap();

    x509_build.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
    let cert = x509_build.build();

    let pkcs12_builder = Pkcs12::builder();
    let pkcs12 = pkcs12_builder
        .build("mypass", subject_name, &pkey, &cert)
        .unwrap();

    (pkey, cert, pkcs12)
}
