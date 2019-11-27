// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-https")]

extern crate chrono;
extern crate futures;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate rustls;
extern crate tokio;
extern crate trust_dns_client;
extern crate trust_dns_https;
extern crate trust_dns_proto;
extern crate trust_dns_server;

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::sync::Arc;

use rustls::{Certificate, ClientConfig, ProtocolVersion, RootCertStore};
use tokio::runtime::Runtime;
use trust_dns_client::client::*;
use trust_dns_https::HttpsClientStreamBuilder;

use server_harness::{named_test_harness, query_a};

#[test]
fn test_example_https_toml_startup() {
    extern crate env_logger;
    env_logger::try_init().ok();

    const ALPN_H2: &[u8] = b"h2";

    named_test_harness("dns_over_https.toml", move |_, _, https_port| {
        let mut cert_der = vec![];
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| ".".to_owned());
        println!("using server src path: {}", server_path);

        File::open(&format!(
            "{}/../tests/test-data/named_test_configs/sec/example.cert",
            server_path
        ))
        .expect("failed to open cert")
        .read_to_end(&mut cert_der)
        .expect("failed to read cert");

        let mut io_loop = Runtime::new().unwrap();
        let addr: SocketAddr = ("127.0.0.1", https_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let versions = vec![ProtocolVersion::TLSv1_2];

        let cert = to_trust_anchor(&cert_der);
        root_store.add(&cert).unwrap();

        let mut client_config = ClientConfig::new();
        client_config.root_store = root_store;
        client_config.versions = versions;
        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        let client_config = Arc::new(client_config);

        let https_conn_builder = HttpsClientStreamBuilder::with_client_config(client_config);

        let mp = https_conn_builder.build(addr, "ns.example.com".to_string());
        let (bg, mut client) = ClientFuture::connect(mp);

        // ipv4 should succeed
        io_loop.spawn(bg);
        query_a(&mut io_loop, &mut client);

        // a second request should work...
        query_a(&mut io_loop, &mut client);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate(cert_der.to_vec())
}
