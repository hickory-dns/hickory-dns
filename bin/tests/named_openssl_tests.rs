// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-openssl")]
#![cfg(not(feature = "dns-over-rustls"))]
// TODO: enable this test for rustls as well using below config
// #![cfg(feature = "dns-over-tls")]

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;

use native_tls::Certificate;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;

use trust_dns_client::client::*;
use trust_dns_proto::native_tls::TlsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;

#[test]
fn test_example_tls_toml_startup() {
    test_startup("dns_over_tls.toml")
}

#[test]
fn test_example_tls_rustls_and_openssl_toml_startup() {
    test_startup("dns_over_tls_rustls_and_openssl.toml")
}

fn test_startup(toml: &'static str) {
    named_test_harness(toml, move |_, _, tls_port, _, _| {
        let mut cert_der = vec![];
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        println!("using server src path: {}", server_path);

        File::open(&format!(
            "{}/tests/test-data/named_test_configs/sec/example.cert",
            server_path
        ))
        .expect("failed to open cert")
        .read_to_end(&mut cert_der)
        .expect("failed to read cert");

        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", tls_port.expect("no tls_port"))
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder =
            TlsClientStreamBuilder::<AsyncIoTokioAsStd<TokioTcpStream>>::new();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) = tls_conn_builder.build(addr, "ns.example.com".to_string());
        let client = AsyncClient::new(stream, sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        trust_dns_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = ("127.0.0.1", tls_port.expect("no tls_port"))
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder =
            TlsClientStreamBuilder::<AsyncIoTokioAsStd<TokioTcpStream>>::new();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) = tls_conn_builder.build(addr, "ns.example.com".to_string());
        let client = AsyncClient::new(stream, sender, None);
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        trust_dns_proto::spawn_bg(&io_loop, bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);

        assert!(true);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate::from_der(cert_der).unwrap()
}
