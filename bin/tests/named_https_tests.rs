// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-https")]

mod server_harness;

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::sync::Arc;

use rustls::{Certificate, ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;
use trust_dns_client::client::*;
use trust_dns_proto::https::HttpsClientStreamBuilder;
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;

use server_harness::{named_test_harness, query_a};

#[test]
fn test_example_https_toml_startup() {
    // env_logger::try_init().ok();

    const ALPN_H2: &[u8] = b"h2";

    named_test_harness("dns_over_https.toml", move |_, _, _, https_port, _| {
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
        let addr: SocketAddr = ("127.0.0.1", https_port.expect("no https_port"))
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        // using the mozilla default root store
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let cert = to_trust_anchor(&cert_der);
        root_store.add(&cert).unwrap();

        let mut client_config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        let client_config = Arc::new(client_config);

        let https_builder = HttpsClientStreamBuilder::with_client_config(client_config);

        let mp = https_builder
            .build::<AsyncIoTokioAsStd<TokioTcpStream>>(addr, "ns.example.com".to_string());
        let client = AsyncClient::connect(mp);

        // ipv4 should succeed
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        trust_dns_proto::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // a second request should work...
        query_a(&mut io_loop, &mut client);
    })
}

fn to_trust_anchor(cert_der: &[u8]) -> Certificate {
    Certificate(cert_der.to_vec())
}
