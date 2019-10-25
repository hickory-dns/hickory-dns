// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-rustls")]

extern crate chrono;
extern crate futures;
#[macro_use]
extern crate log;
extern crate rustls;
extern crate tokio;
extern crate trust_dns_client;
extern crate trust_dns_proto;
extern crate trust_dns_rustls;
extern crate trust_dns_server;

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::sync::Arc;

use rustls::Certificate;
use rustls::ClientConfig;
use tokio::runtime::current_thread::Runtime;

use trust_dns_client::client::*;
use trust_dns_rustls::tls_client_connect;

use server_harness::{named_test_harness, query_a};

#[test]
fn test_example_tls_toml_startup() {
    named_test_harness(
        "dns_over_tls_rustls_and_openssl.toml",
        move |_, tls_port, _| {
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
            let addr: SocketAddr = ("127.0.0.1", tls_port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();

            let cert = to_trust_anchor(&cert_der);
            let mut config = ClientConfig::new();
            config.root_store.add(&cert).expect("bad certificate");
            let config = Arc::new(config);

            let (stream, sender) =
                tls_client_connect(addr, "ns.example.com".to_string(), config.clone());
            let (bg, mut client) = ClientFuture::new(stream, Box::new(sender), None);

            // ipv4 should succeed
            io_loop.spawn(bg);
            query_a(&mut io_loop, &mut client);

            let addr: SocketAddr = ("127.0.0.1", tls_port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();
            let (stream, sender) =
                tls_client_connect(addr, "ns.example.com".to_string(), config.clone());
            let (bg, mut client) = ClientFuture::new(stream, Box::new(sender), None);
            io_loop.spawn(bg);

            // ipv6 should succeed
            query_a(&mut io_loop, &mut client);
        },
    )
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate(cert_der.to_vec())
}
