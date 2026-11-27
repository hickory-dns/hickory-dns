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
use rustls::{ClientConfig, KeyLogFile, ServerConfig, sign::SingleCertAndKey, version::TLS13};
use test_support::{TestCertificates, subscribe};
use tokio::net::UdpSocket;

use crate::{
    proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    },
    quic::{QuicClientStreamBuilder, QuicStreams},
    tls::default_provider,
    xfer::DnsRequestSender,
};

use super::{quic_server::QuicServer, quic_stream::DOQ_ALPN};

async fn server_responder(mut server: QuicServer) {
    while let Some(incoming) = server.next().await {
        println!("received client request {}", incoming.remote_address());

        let connecting = incoming
            .accept()
            .expect("failed to accept next quic connection");
        let mut conn = QuicStreams::new(connecting)
            .await
            .expect("failed to establish next quic connection");
        while let Some(stream) = conn.next().await {
            let mut stream = stream.expect("new client stream failed");

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

    let mut server_config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(certificate_and_key));
    server_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];

    // All testing is only done on local addresses, construct the server
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let quic_ns = QuicServer::new(socket.try_into().unwrap(), Arc::new(server_config))
        .expect("failed to initialize QuicServer");

    // kick off the server
    let server_addr = quic_ns.local_addr().expect("no address");
    println!("testing quic on: {server_addr}");
    let server_join = tokio::spawn(server_responder(quic_ns));

    // now construct the client
    let mut roots = rustls::RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates([certificates.ca.der().clone()]);
    assert_eq!(ignored, 0);

    let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
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
