// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(
    unused_imports,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::single_component_path_imports
)]

use std::env;
use std::fs::File;
use std::io::{Read, Write};
#[cfg(not(target_os = "linux"))]
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic;
use std::sync::Arc;
use std::{thread, time};

use futures_util::stream::StreamExt;
use native_tls;
use native_tls::{Certificate, TlsAcceptor};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;

#[allow(clippy::useless_attribute)]
#[allow(unused)]
use crate::native_tls::{TlsStream, TlsStreamBuilder};
use crate::xfer::SerialMessage;
use crate::{iocompat::AsyncIoTokioAsStd, DnsStreamHandle};

// this fails on linux for some reason. It appears that a buffer somewhere is dirty
//  and subsequent reads of a message buffer reads the wrong length. It works for 2 iterations
//  but not 3?
// #[cfg(not(target_os = "linux"))]
#[test]
#[cfg_attr(target_os = "macos", ignore)] // TODO: add back once https://github.com/sfackler/rust-native-tls/issues/143 is fixed
fn test_tls_client_stream_ipv4() {
    tls_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), false)
}

// FIXME: mtls is disabled at the moment, it causes a hang on Linux, and is currently not supported on macOS
#[cfg(feature = "mtls")]
#[test]
#[cfg(not(target_os = "macos"))]
fn test_tls_client_stream_ipv4_mtls() {
    tls_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), true)
}

#[test]
#[cfg_attr(target_os = "macos", ignore)] // TODO: add back once https://github.com/sfackler/rust-native-tls/issues/143 is fixed
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
#[cfg(not(target_os = "macos"))] // certificates are failing on macOS now
fn test_tls_client_stream_ipv6() {
    tls_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), false)
}

const TEST_BYTES: &[u8; 8] = b"DEADBEEF";
const TEST_BYTES_LEN: usize = 8;

fn read_file(path: &str) -> Vec<u8> {
    let mut bytes = vec![];

    let mut file = File::open(path).unwrap_or_else(|_| panic!("failed to open file: {}", path));
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("failed to read file: {}", path));
    bytes
}

#[allow(unused, unused_mut)]
fn tls_client_stream_test(server_addr: IpAddr, mtls: bool) {
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
    println!("using server src path: {}", server_path);

    let root_cert_der = read_file(&format!("{}/tests/test-data/ca.der", server_path));

    // Generate X509 certificate
    let dns_name = "ns.example.com";
    let server_pkcs12_der = read_file(&format!("{}/tests/test-data/cert.p12", server_path));

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let send_recv_times = 4;

    let server_handle = thread::Builder::new()
        .name("test_tls_client_stream:server".to_string())
        .spawn(move || {
            let pkcs12 = native_tls::Identity::from_pkcs12(&server_pkcs12_der, "mypass")
                .expect("Identity::from_pkcs12");
            let mut tls = TlsAcceptor::builder(pkcs12);

            // #[cfg(target_os = "linux")]
            // {
            //   let mut openssl_builder = tls.builder_mut();
            //   let mut openssl_ctx_builder = openssl_builder.builder_mut();

            //   let mut mode = openssl::ssl::SslVerifyMode::empty();

            //   // TODO: mtls tests hang on Linux...
            //   if mtls {
            //     //   mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

            //     // let mut store = X509StoreBuilder::new().unwrap();
            //     // let root_ca = X509::from_der(&root_cert_der_copy).unwrap();
            //     // store.add_cert(root_ca).unwrap();
            //     // openssl_ctx_builder.set_verify_cert_store(store.build()).unwrap();
            //   } else {
            //     mode.insert(SSL_VERIFY_NONE);
            //   }

            //   openssl_ctx_builder.set_verify(mode);
            // }

            // TODO: add CA on macOS

            let tls = tls.build().expect("tls build failed");

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

    let trust_chain = Certificate::from_der(&root_cert_der).unwrap();

    // barrier.wait();
    let mut builder = TlsStreamBuilder::<AsyncIoTokioAsStd<TokioTcpStream>>::new();
    builder.add_ca(trust_chain);

    // fix MTLS
    // if mtls {
    //     config_mtls(&root_pkey, &root_name, &root_cert, &mut builder);
    // }

    let (stream, mut sender) = builder.build(server_addr, dns_name.to_string());

    // TODO: there is a race failure here... a race with the server thread most likely...
    let mut stream = io_loop.block_on(stream).expect("run failed to get stream");

    for _ in 0..send_recv_times {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = io_loop.block_on(stream.into_future());
        stream = stream_tmp;
        let message = buffer.expect("no buffer received");
        assert_eq!(
            message.expect("message destructure failed").bytes(),
            TEST_BYTES
        );
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}

// TODO: fix MTLS
// #[allow(unused_variables)]
// fn config_mtls(root_pkey: &PKey,
//                root_name: &X509Name,
//                root_cert: &X509,
//                builder: &mut TlsStreamBuilder) {
//     // signed by the same root cert
//     let client_name = "resolv.example.com";
//     let (_ /*client_pkey*/, _ /*client_cert*/, client_identity) =
//         cert(client_name, root_pkey, root_name, root_cert);
//     let client_identity =
//         native_tls::Pkcs12::from_der(&client_identity.to_der().unwrap(), "mypass").unwrap();

//     #[cfg(feature = "mtls")]
//     builder.identity(client_identity);
// }
