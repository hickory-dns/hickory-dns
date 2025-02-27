// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::print_stdout)] // this is a test module

use alloc::{borrow::ToOwned, string::ToString, sync::Arc, vec::Vec};
use core::str::FromStr;
use std::{env, net::SocketAddr, path::Path, println};

use futures_util::StreamExt;
use rustls::{
    ClientConfig, KeyLogFile,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
    sign::{CertifiedKey, SingleCertAndKey},
};
use test_support::subscribe;

use crate::{
    op::{Message, Query},
    quic::QuicClientStreamBuilder,
    rr::{Name, RecordType},
    rustls::default_provider,
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
                .send(client_message.into_message())
                .await
                .expect("failed to send response")
        }
    }
}

#[tokio::test]
async fn test_quic_stream() {
    subscribe();

    let dns_name = "ns.example.com";

    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    println!("using server src path: {server_path}");

    let ca = read_certs(format!("{server_path}/tests/test-data/ca.pem")).unwrap();
    let cert_chain = read_certs(format!("{server_path}/tests/test-data/cert.pem")).unwrap();

    let key =
        PrivateKeyDer::from_pem_file(format!("{server_path}/tests/test-data/cert.key")).unwrap();

    let certificate_and_key = SingleCertAndKey::from(
        CertifiedKey::from_der(cert_chain, key, &default_provider()).unwrap(),
    );

    // All testing is only done on local addresses, construct the server
    let quic_ns = QuicServer::new(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        Arc::new(certificate_and_key),
    )
    .await
    .expect("failed to initialize QuicServer");

    // kick off the server
    let server_addr = quic_ns.local_addr().expect("no address");
    println!("testing quic on: {server_addr}");
    let server_join = tokio::spawn(server_responder(quic_ns));

    // now construct the client
    let mut roots = rustls::RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates(ca.into_iter());
    assert_eq!(ignored, 0);

    let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
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

fn read_certs(cert_path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, pem::Error> {
    CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()
}
