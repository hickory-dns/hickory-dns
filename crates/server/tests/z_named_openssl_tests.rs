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

extern crate chrono;
extern crate futures;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate tokio;
extern crate trust_dns;
extern crate trust_dns_native_tls;
extern crate trust_dns_proto;
extern crate trust_dns_server;

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;

use native_tls::Certificate;
use tokio::runtime::current_thread::Runtime;

use trust_dns::client::*;
use trust_dns_native_tls::TlsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};

#[test]
fn test_example_tls_toml_startup() {
    test_startup("dns_over_tls.toml")
}

#[test]
fn test_example_tls_rustls_and_openssl_toml_startup() {
    test_startup("dns_over_tls_rustls_and_openssl.toml")
}

fn test_startup(toml: &'static str) {
    named_test_harness(toml, move |_, tls_port, _| {
        let mut cert_der = vec![];
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| ".".to_owned());
        println!("using server src path: {}", server_path);

        File::open(&format!(
            "{}/tests/named_test_configs/sec/example.cert",
            server_path
        )).expect("failed to open cert")
        .read_to_end(&mut cert_der)
        .expect("failed to read cert");

        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStreamBuilder::new();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) = tls_conn_builder.build(addr, "ns.example.com".to_string());
        let (bg, mut client) = ClientFuture::new(stream, Box::new(sender), None);

        // ipv4 should succeed
        io_loop.spawn(bg);
        query_a(&mut io_loop, &mut client);

        let addr: SocketAddr = ("127.0.0.1", tls_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let mut tls_conn_builder = TlsClientStreamBuilder::new();
        let cert = to_trust_anchor(&cert_der);
        tls_conn_builder.add_ca(cert);
        let (stream, sender) = tls_conn_builder.build(addr, "ns.example.com".to_string());
        let (bg, mut client) = ClientFuture::new(stream, Box::new(sender), None);
        io_loop.spawn(bg);

        // ipv6 should succeed
        query_a(&mut io_loop, &mut client);

        assert!(true);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate::from_der(cert_der).unwrap()
}
