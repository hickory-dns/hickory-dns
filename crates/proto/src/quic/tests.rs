// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{env, net::SocketAddr, path::Path, str::FromStr, sync::Arc};

use futures_util::StreamExt;
use rustls::{ClientConfig, KeyLogFile};

use crate::{
    op::{Message, Query},
    quic::QuicClientStreamBuilder,
    rr::{Name, RecordType},
    rustls::tls_server,
    xfer::DnsRequestSender,
};

use super::quic_server::QuicServer;

async fn server_responder(mut server: QuicServer) {
    while let Some((mut conn, addr)) = server
        .next()
        .await
        .expect("failed to get next quic session")
    {
        println!("received client request {addr}");

        while let Some(stream) = conn.next().await {
            let mut stream = stream.expect("new client stream failed");

            let client_message = stream.receive().await.expect("failed to receive");

            // just response with the same message.
            stream
                .send(client_message)
                .await
                .expect("failed to send response")
        }
    }
}

#[tokio::test]
async fn test_quic_stream() {
    let dns_name = "ns.example.com";

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    println!("using server src path: {}", server_path);

    let ca = tls_server::read_cert(Path::new(&format!(
        "{}/tests/test-data/ca.pem",
        server_path
    )))
    .map_err(|e| format!("error reading cert: {}", e))
    .unwrap();
    let cert = tls_server::read_cert(Path::new(&format!(
        "{}/tests/test-data/cert.pem",
        server_path
    )))
    .map_err(|e| format!("error reading cert: {}", e))
    .unwrap();
    let key = tls_server::read_key_from_pem(Path::new(&format!(
        "{}/tests/test-data/cert-key.pem",
        server_path
    )))
    .unwrap();

    // All testing is only done on local addresses, construct the server
    let quic_ns = QuicServer::new(SocketAddr::from(([127, 0, 0, 1], 0)), cert, key)
        .await
        .expect("failed to initialize QuicServer");

    // kick off the server
    let server_addr = quic_ns.local_addr().expect("no address");
    println!("testing quic on: {}", server_addr);
    let server_join = tokio::spawn(server_responder(quic_ns));

    // now construct the client
    let mut roots = rustls::RootCertStore::empty();
    ca.iter()
        .try_for_each(|ca| roots.add(ca))
        .expect("failed to build roots");
    let mut client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_config.key_log = Arc::new(KeyLogFile::new());

    let mut builder = QuicClientStreamBuilder::default();
    builder.crypto_config(client_config);

    println!("starting quic connect");
    let mut client_stream = builder
        .build(server_addr, dns_name.to_string())
        .await
        .expect("failed to connect");

    println!("connected client to server");

    // create a test message, send and then receive...
    let mut message = Message::default();
    message.add_query(Query::query(
        Name::from_str("www.example.test.").unwrap(),
        RecordType::AAAA,
    ));

    // TODO: we should make the finalizer easier to call so this round-trip serialization isn't necessary.
    let bytes = message.to_vec().unwrap();
    let message = Message::from_vec(&bytes).unwrap();

    let response = client_stream
        .send_message(message.clone().into())
        .next()
        .await
        .expect("no response received")
        .expect("failed to read response");

    assert_eq!(*response, message);

    // and finally kill the server
    server_join.abort();
}
