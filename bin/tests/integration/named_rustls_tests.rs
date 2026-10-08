// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "__tls")]

use std::env;
use std::net::*;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use test_support::subscribe;

use crate::server_harness::{TestServer, query_a, tls::prepare_certificates};
use hickory_net::client::Client;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tls::{tls_client_connect, tls_config};
use hickory_net::xfer::Protocol;

#[tokio::test]
async fn test_example_tls_toml_startup() {
    subscribe();

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
    println!("using server src path: {server_path}");
    let ca_cert = prepare_certificates(&server_path);

    let server = TestServer::start("dns_over_tls_rustls_and_openssl.toml");
    let tls_port = server.ports.get_v4(Protocol::Tls);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tls_port.expect("no tls_port")));
    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert.clone()).expect("bad certificate");

    let config = ClientConfig::builder_with_provider(Arc::new(tls_config::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let config = Arc::new(config);
    let provider = TokioRuntimeProvider::new();
    let (future, sender) = tls_client_connect(
        addr,
        ServerName::try_from("ns.example.com").unwrap(),
        config.clone(),
        provider.clone(),
    );
    let stream = future.await.expect("client failed to connect");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv4 should succeed
    query_a(&mut client).await;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tls_port.expect("no tls_port")));
    let (future, sender) = tls_client_connect(
        addr,
        ServerName::try_from("ns.example.com").unwrap(),
        config,
        provider,
    );
    let stream = future.await.expect("client failed to connect");
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    tokio::spawn(bg);

    // ipv6 should succeed
    query_a(&mut client).await;
}
