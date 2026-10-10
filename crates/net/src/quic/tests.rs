// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::print_stdout)] // this is a test module

use core::{net::SocketAddr, str::FromStr};
use std::println;
use std::sync::Arc;

use futures_util::StreamExt;
use rustls::{ClientConfig, KeyLogFile, sign::SingleCertAndKey};
use test_support::{TestCertificates, subscribe};

use crate::{
    proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    },
    quic::QuicClientStreamBuilder,
    tls::tls_config,
    xfer::DnsRequestSender,
};

use super::quic_listener::QuicListener;

async fn server_responder(mut listener: QuicListener) {
    if let Some(connection) = listener.accept(None).await {
        let mut conn = connection.expect("failed to accept next quic connection");
        println!("received client request {}", conn.src_addr);
        loop {
            let mut stream = conn
                .connection
                .accept()
                .await
                .expect("new client stream failed");

            let bytes = stream.receive_bytes().await.expect("failed to receive");
            let client_message = Message::from_vec(&bytes).expect("failed to parse message");

            // just respond with the same message converted to a response.
            stream
                .send(client_message.into_response())
                .await
                .expect("failed to send response")
        }
    }
}

#[tokio::test]
async fn test_quic_stream() {
    subscribe();

    let certificates = TestCertificates::generate();
    let certificate_and_key = SingleCertAndKey::from(certificates.certified_key());

    // All testing is only done on local addresses, construct the server
    let quic_ns = QuicListener::new(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        Arc::new(certificate_and_key),
    )
    .await
    .expect("failed to initialize QuicListener");

    // kick off the server
    let server_addr = quic_ns.local_addr().expect("no address");
    println!("testing quic on: {server_addr}");
    let server_join = tokio::spawn(server_responder(quic_ns));

    // now construct the client
    let mut roots = rustls::RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates([certificates.ca.der().clone()]);
    assert_eq!(ignored, 0);

    let mut client_config = ClientConfig::builder_with_provider(Arc::new(tls_config::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_config.key_log = Arc::new(KeyLogFile::new());

    println!("starting quic connect");
    let builder = QuicClientStreamBuilder::default().crypto_config(client_config);
    let mut client_stream = builder
        .build(server_addr, Arc::from("ns.example.com"))
        .await
        .expect("failed to connect");

    println!("connected client to server");

    // create a test message, send and then receive...
    let mut message = Message::query();
    message.add_query(Query::new(
        Name::from_str("www.example.test.").unwrap(),
        RecordType::AAAA,
    ));
    message.metadata.id = 0; // RFC: DNS over QUIC requires the Message ID to be 0

    // TODO: we should make the finalizer easier to call so this round-trip serialization isn't necessary.
    let bytes = message.to_vec().unwrap();
    let message = Message::from_vec(&bytes).unwrap();

    let response = client_stream
        .send_message(message.clone().into())
        .next()
        .await
        .expect("no response received")
        .expect("failed to read response");

    assert_eq!(*response, message.into_response());

    // and finally kill the server
    server_join.abort();
}
