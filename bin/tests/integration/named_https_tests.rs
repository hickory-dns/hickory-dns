// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "__https")]

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio::runtime::Runtime;

use crate::server_harness::{named_test_harness, query_a};
use hickory_client::client::Client;
use hickory_proto::h2::HttpsClientStreamBuilder;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::rustls::default_provider;
use hickory_proto::xfer::Protocol;
use test_support::subscribe;

#[test]
fn test_example_https_toml_startup() {
    subscribe();

    const ALPN_H2: &[u8] = b"h2";

    named_test_harness("dns_over_https.toml", move |socket_ports| {
        let mut cert_der = vec![];
        let https_port = socket_ports.get_v4(Protocol::Https);
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        println!("using server src path: {server_path}");

        File::open(format!(
            "{server_path}/tests/test-data/test_configs/sec/example.cert"
        ))
        .expect("failed to open cert")
        .read_to_end(&mut cert_der)
        .expect("failed to read cert");

        let mut io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port.expect("no https_port")));
        std::thread::sleep(std::time::Duration::from_secs(1));

        // using the mozilla default root store
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        root_store.add(CertificateDer::from(cert_der)).unwrap();

        let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        let client_config = Arc::new(client_config);

        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStreamBuilder::with_client_config(client_config, provider);
        let mp = https_builder.build(addr, "ns.example.com".to_string(), "/dns-query".to_string());
        let client = Client::connect(mp);

        // ipv4 should succeed
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // a second request should work...
        query_a(&mut io_loop, &mut client);
    })
}
