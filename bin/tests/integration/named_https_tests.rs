// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "__https")]

use std::env;
use std::net::*;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::server_harness::tls::prepare_certificates;
use crate::server_harness::{TestServer, query_a};
use hickory_net::client::Client;
use hickory_net::h2::HttpsClientStream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tls::{alpn, tls_config};
use hickory_net::xfer::Protocol;
use test_support::subscribe;

#[tokio::test]
async fn test_example_https_toml_startup() {
    subscribe();

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    println!("using server src path: {server_path}");
    let ca_cert = prepare_certificates(&server_path);

    let server = TestServer::start("dns_over_https.toml");
    let https_port = server.ports.get_v4(Protocol::Https);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port.expect("no https_port")));
    std::thread::sleep(std::time::Duration::from_secs(1));

    // using the mozilla default root store
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    root_store.add(ca_cert.clone()).unwrap();

    let mut client_config =
        ClientConfig::builder_with_provider(Arc::new(tls_config::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
    client_config.alpn_protocols.push(alpn::H2.to_vec());

    let client_config = Arc::new(client_config);
    let provider = TokioRuntimeProvider::new();
    let sender = HttpsClientStream::builder(client_config, provider)
        .build(addr, Arc::from("ns.example.com"), Arc::from("/dns-query"))
        .await
        .unwrap();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    // a second request should work...
    query_a(&mut client).await;
}
