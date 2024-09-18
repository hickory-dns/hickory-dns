// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(windows))]
#![cfg(feature = "dns-over-rustls")]

use std::env;
use std::fs::File;
use std::io::*;
use std::net::*;
use std::sync::Arc;

use hickory_server::server::Protocol;
use rustls::pki_types::CertificateDer;
use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;

use hickory_client::client::AsyncClient;
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_proto::rustls::tls_client_connect;

use crate::server_harness::{named_test_harness, query_a};

#[test]
fn test_example_tls_toml_startup() {
    named_test_harness(
        "dns_over_tls_rustls_and_openssl.toml",
        move |socket_ports| {
            let mut cert_der = vec![];
            let tls_port = socket_ports.get_v4(Protocol::Tls);
            let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());
            println!("using server src path: {server_path}");

            File::open(format!(
                "{server_path}/tests/test-data/test_configs/sec/example.cert"
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

            let mut root_store = RootCertStore::empty();
            root_store
                .add(CertificateDer::from(cert_der))
                .expect("bad certificate");

            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let config = Arc::new(config);

            let (stream, sender) = tls_client_connect::<AsyncIoTokioAsStd<TokioTcpStream>>(
                addr,
                "ns.example.com".to_string(),
                config.clone(),
            );
            let client = AsyncClient::new(stream, sender, None);

            let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
            hickory_proto::runtime::spawn_bg(&io_loop, bg);

            // ipv4 should succeed
            query_a(&mut io_loop, &mut client);

            let addr: SocketAddr = ("127.0.0.1", tls_port.expect("no tls_port"))
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();
            let (stream, sender) = tls_client_connect::<AsyncIoTokioAsStd<TokioTcpStream>>(
                addr,
                "ns.example.com".to_string(),
                config,
            );
            let client = AsyncClient::new(stream, sender, None);

            let (mut client, bg) = io_loop.block_on(client).expect("client failed to connect");
            hickory_proto::runtime::spawn_bg(&io_loop, bg);

            // ipv6 should succeed
            query_a(&mut io_loop, &mut client);
        },
    )
}
