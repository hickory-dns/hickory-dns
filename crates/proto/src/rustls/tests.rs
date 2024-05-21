// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::dbg_macro, clippy::print_stdout)]

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic;
use std::sync::Arc;
use std::{thread, time};

use openssl::pkey::PKey;
use openssl::ssl::*;
use openssl::x509::*;

use futures_util::stream::StreamExt;
use rustls::ClientConfig;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;

use crate::rustls::tls_connect;
use crate::xfer::SerialMessage;
use crate::{iocompat::AsyncIoTokioAsStd, DnsStreamHandle};

// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a message buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
#[test]
fn test_tls_client_stream_ipv4() {
    tls_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

#[test]
fn test_tls_client_stream_ipv6() {
    tls_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

const TEST_BYTES: &[u8; 8] = b"DEADBEEF";
const TEST_BYTES_LEN: usize = 8;

fn read_file(path: &str) -> Vec<u8> {
    let mut bytes = vec![];

    let mut file = File::open(path).unwrap_or_else(|_| panic!("failed to open file: {}", path));
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("failed to open file: {}", path));
    bytes
}

#[allow(unused_mut)]
fn tls_client_stream_test(server_addr: IpAddr) {
    let succeeded = Arc::new(atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                thread::sleep(time::Duration::from_secs(1));
                if succeeded.load(atomic::Ordering::Relaxed) {
                    return;
                }
            }

            println!("Thread Killer has been awoken, killing process");
            std::process::exit(-1);
        })
        .unwrap();

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    println!("using server src path: {server_path}");

    let root_cert_der = read_file(&format!("{server_path}/tests/test-data/ca.der"));

    // Generate X509 certificate
    let ca = X509::from_der(&root_cert_der).expect("could not read CA");
    let dns_name = "ns.example.com";
    let cert = X509::from_pem(&read_file(&format!(
        "{server_path}/tests/test-data/cert.pem"
    )))
    .expect("could not read cert pem");

    let private_key = PKey::private_key_from_pem(&read_file(&format!(
        "{server_path}/tests/test-data/cert.key"
    )))
    .expect("could not read public key");

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let send_recv_times = 4;

    let server_handle = thread::Builder::new()
        .name("test_tls_client_stream:server".to_string())
        .spawn(move || {
            let mut tls =
                SslAcceptor::mozilla_modern(SslMethod::tls()).expect("mozilla_modern failed");
            tls.set_private_key(private_key.as_ref())
                .expect("failed to associated key");
            tls.set_certificate(&cert)
                .expect("failed to associated cert");

            tls.add_extra_chain_cert(ca.to_owned())
                .expect("failed to add chain");

            {
                let mut openssl_ctx_builder = &mut tls;
                let mut mode = SslVerifyMode::empty();
                mode.insert(SslVerifyMode::NONE);
                openssl_ctx_builder.set_verify(mode);
            }

            // FIXME: add CA on macOS

            let tls = tls.build();

            // server_barrier.wait();
            let (socket, _) = server.accept().expect("tcp accept failed");
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...

            let mut socket = tls.accept(socket).expect("tls accept failed");

            for _ in 0..send_recv_times {
                // wait for some bytes...
                let mut len_bytes = [0_u8; 2];
                socket
                    .read_exact(&mut len_bytes)
                    .expect("SERVER: receive failed");
                let length =
                    u16::from(len_bytes[0]) << 8 & 0xFF00 | u16::from(len_bytes[1]) & 0x00FF;
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
    let mut io_loop = Runtime::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));

    let mut roots = rustls::RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates(&[root_cert_der]);
    assert_eq!(ignored, 0, "bad certificate!");
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let (stream, mut sender) = tls_connect::<AsyncIoTokioAsStd<TokioTcpStream>>(
        server_addr,
        dns_name.to_string(),
        Arc::new(config),
    );

    // TODO: there is a race failure here... a race with the server thread most likely...
    let mut stream = io_loop.block_on(stream).expect("run failed to get stream");

    for _ in 0..send_recv_times {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = io_loop.block_on(stream.into_future());
        stream = stream_tmp;
        let message = buffer
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(message.bytes(), TEST_BYTES);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
