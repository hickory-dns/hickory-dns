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

use crate::server_harness::{TestServer, query_a};
use hickory_net::client::Client;
use hickory_net::quic::QuicClientStream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::rustls::default_provider;
use hickory_net::xfer::Protocol;
use test_support::subscribe;

#[tokio::test]
async fn test_example_quic_toml_startup() {
    subscribe();

    let server = TestServer::start("dns_over_quic.toml");
    let mut cert_der = vec![];
    let quic_port = server.ports.get_v4(Protocol::Quic);
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    println!("using server src path: {server_path} and quic_port: {quic_port:?}");

    File::open(format!(
        "{server_path}/tests/test-data/test_configs/sec/example.cert"
    ))
    .expect("failed to open cert")
    .read_to_end(&mut cert_der)
    .expect("failed to read cert");

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

    let client = Client::<TokioRuntimeProvider>::connect(
        QuicClientStream::builder()
            .crypto_config(client_config)
            .build(addr, Arc::from("ns.example.com")),
    );

    // ipv4 should succeed
    let (mut client, bg) = client.await.expect("client failed to connect");
    tokio::spawn(bg);

    query_a(&mut client).await;

    // a second request should work...
    query_a(&mut client).await;
}
