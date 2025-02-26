// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "__quic")]

use std::{env, fs::File, io::*, net::*, sync::Arc};

use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use tokio::runtime::Runtime;

use crate::server_harness::{named_test_harness, query_a};
use hickory_client::client::Client;
use hickory_proto::quic::QuicClientStream;
use hickory_proto::rustls::default_provider;
use hickory_proto::xfer::Protocol;
use test_support::subscribe;

#[test]
fn test_example_quic_toml_startup() {
    subscribe();

    named_test_harness("dns_over_quic.toml", move |socket_ports| {
        let mut cert_der = vec![];
        let quic_port = socket_ports.get_v4(Protocol::Quic);
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
        println!("using server src path: {server_path} and quic_port: {quic_port:?}");

        File::open(format!(
            "{server_path}/tests/test-data/test_configs/sec/example.cert"
        ))
        .expect("failed to open cert")
        .read_to_end(&mut cert_der)
        .expect("failed to read cert");

        let mut io_loop = Runtime::new().unwrap();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, quic_port.expect("no quic_port")));
        std::thread::sleep(std::time::Duration::from_secs(1));

        // using the mozilla default root store
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store.add(CertificateDer::from(cert_der)).unwrap();

        let client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut quic_builder = QuicClientStream::builder();
        quic_builder.crypto_config(client_config);

        let mp = quic_builder.build(addr, "ns.example.com".to_string());
        let client = Client::connect(mp);

        // ipv4 should succeed
        let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
        hickory_proto::runtime::spawn_bg(&io_loop, bg);

        query_a(&mut io_loop, &mut client);

        // a second request should work...
        query_a(&mut io_loop, &mut client);
    })
}
