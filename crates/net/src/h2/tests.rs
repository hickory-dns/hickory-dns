// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::Stream;
use test_support::subscribe;

use super::*;
use crate::http::{RequestContext, Version};
use crate::proto::op::Message;

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
use {
    crate::proto::op::{DnsRequest, DnsRequestOptions, Edns, Query},
    crate::proto::rr::{Name, RData, RecordType},
    crate::runtime::TokioRuntimeProvider,
    crate::tls::{alpn, tls_config},
    crate::xfer::{DnsRequestSender, FirstAnswer},
    core::net::SocketAddr,
    core::str::FromStr,
    rustls::{ClientConfig, KeyLogFile},
};

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[tokio::test]
async fn test_https_google() {
    subscribe();

    let google = SocketAddr::from(([8, 8, 8, 8], 443));
    let mut request = Message::query();
    let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    request.add_query(query);
    request.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    request.edns = Some(edns);

    let request = DnsRequest::new(request, DnsRequestOptions::default());

    let mut client_config = client_config_h2();
    client_config.key_log = Arc::new(KeyLogFile::new());

    let provider = TokioRuntimeProvider::new();
    let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
    let connect = https_builder.build(google, Arc::from("dns.google"), Arc::from("/dns-query"));

    let mut https = connect.await.expect("https connect failed");

    let response = https
        .send_message(request)
        .first_answer()
        .await
        .expect("send_message failed");

    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(_)))
    );

    //
    // assert that the connection works for a second query
    let mut request = Message::query();
    let query = Query::new(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::AAAA,
    );
    request.add_query(query);
    request.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    request.edns = Some(edns);

    let request = DnsRequest::new(request, DnsRequestOptions::default());

    let response = https
        .send_message(request.clone())
        .first_answer()
        .await
        .expect("send_message failed");

    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::AAAA(_)))
    );
}

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[tokio::test]
async fn test_https_google_with_pure_ip_address_server() {
    subscribe();

    let google = SocketAddr::from(([8, 8, 8, 8], 443));
    let mut request = Message::query();
    let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    request.add_query(query);
    request.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    request.edns = Some(edns);

    let request = DnsRequest::new(request, DnsRequestOptions::default());

    let mut client_config = client_config_h2();
    client_config.key_log = Arc::new(KeyLogFile::new());

    let provider = TokioRuntimeProvider::new();
    let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
    let connect = https_builder.build(
        google,
        Arc::from(google.ip().to_string()),
        Arc::from("/dns-query"),
    );

    let mut https = connect.await.expect("https connect failed");

    let response = https
        .send_message(request)
        .first_answer()
        .await
        .expect("send_message failed");

    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(_)))
    );

    //
    // assert that the connection works for a second query
    let mut request = Message::query();
    let query = Query::new(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::AAAA,
    );
    request.add_query(query);
    request.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    request.edns = Some(edns);

    let request = DnsRequest::new(request, DnsRequestOptions::default());

    let response = https
        .send_message(request.clone())
        .first_answer()
        .await
        .expect("send_message failed");

    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::AAAA(_)))
    );
}

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
#[tokio::test]
#[ignore = "cloudflare has been unreliable as a public test service"]
async fn test_https_cloudflare() {
    subscribe();

    let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
    let mut request = Message::query();
    let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
    request.add_query(query);
    request.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    request.edns = Some(edns);

    let request = DnsRequest::new(request, DnsRequestOptions::default());

    let client_config = client_config_h2();
    let provider = TokioRuntimeProvider::new();
    let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
    let connect = https_builder.build(
        cloudflare,
        Arc::from("cloudflare-dns.com"),
        Arc::from("/dns-query"),
    );

    let mut https = connect.await.expect("https connect failed");

    let response = https
        .send_message(request)
        .first_answer()
        .await
        .expect("send_message failed");

    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(_)))
    );

    //
    // assert that the connection works for a second query
    let mut request = Message::query();
    let query = Query::new(
        Name::from_str("www.example.com.").unwrap(),
        RecordType::AAAA,
    );
    request.add_query(query);
    request.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    request.edns = Some(edns);

    let request = DnsRequest::new(request, DnsRequestOptions::default());

    let response = https
        .send_message(request)
        .first_answer()
        .await
        .expect("send_message failed");

    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::AAAA(_)))
    );
}

#[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
fn client_config_h2() -> ClientConfig {
    let mut config = tls_config::client().unwrap();
    config.alpn_protocols = vec![alpn::H2.to_vec()];
    config
}

#[tokio::test]
async fn test_from_post() {
    subscribe();
    let message = Message::query();
    let msg_bytes = message.to_vec().unwrap();
    let len = msg_bytes.len();
    let stream = TestBytesStream(vec![Ok(Bytes::from(msg_bytes))]);
    let cx = RequestContext {
        version: Version::Http2,
        server_name: Arc::from("ns.example.com"),
        query_path: Arc::from("/dns-query"),
        set_headers: None,
    };

    let request = cx.build(len).unwrap();
    let request = request.map(|()| stream);

    let bytes = message_from(
        Some(Arc::from("ns.example.com")),
        "/dns-query".into(),
        request,
    )
    .await
    .unwrap();

    let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
    assert_eq!(message, msg_from_post);
}

#[derive(Debug)]
struct TestBytesStream(Vec<Result<Bytes, h2::Error>>);

impl Stream for TestBytesStream {
    type Item = Result<Bytes, h2::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.pop() {
            Some(Ok(bytes)) => Poll::Ready(Some(Ok(bytes))),
            Some(Err(err)) => Poll::Ready(Some(Err(err))),
            None => Poll::Ready(None),
        }
    }
}
