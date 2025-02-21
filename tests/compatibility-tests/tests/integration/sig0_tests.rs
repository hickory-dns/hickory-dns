// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(feature = "none"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration;

use hickory_client::client::Client;
use hickory_client::client::ClientHandle;
use hickory_client::proto::dnssec::crypto::RsaSigningKey;
use hickory_client::proto::dnssec::rdata::key::{KEY, KeyUsage};
use hickory_client::proto::dnssec::{Algorithm, SigSigner, SigningKey};
use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::rdata::A;
use hickory_client::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use hickory_compatibility::named_process;

#[tokio::test]
async fn test_get() {
    test_support::subscribe();

    let (_process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let conn = UdpClientStream::builder(socket, TokioRuntimeProvider::default()).build();
    let (mut client, driver) = Client::connect(conn).await.expect("failed to connect");
    tokio::spawn(driver);

    let name = Name::from_str("www.example.com.").unwrap();
    let result = client
        .query(name, DNSClass::IN, RecordType::A)
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0].record_type(), RecordType::A);

    let rdata = result.answers()[0].data();
    if let RData::A(address) = rdata {
        assert_eq!(address, &A::new(127, 0, 0, 1));
    } else {
        panic!("RData::A wasn't here");
    }
}

#[tokio::test]
async fn test_create() {
    test_support::subscribe();

    const KEY: &[u8] = include_bytes!("../conf/Kupdate.example.com.+008+56935.pk8");
    let key =
        RsaSigningKey::from_pkcs8(&PrivatePkcs8KeyDer::from(KEY), Algorithm::RSASHA256).unwrap();
    let sig0key = KEY::new(
        Default::default(),
        KeyUsage::Entity,
        Default::default(),
        Default::default(),
        Algorithm::RSASHA256,
        key.to_public_key().unwrap().into_inner(),
    );

    let signer = SigSigner::sig0(
        sig0key,
        Box::new(key),
        Name::from_str("update.example.com.").unwrap(),
    );
    assert_eq!(signer.calculate_key_tag().unwrap(), 56935);

    let (_process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let conn = UdpClientStream::builder(socket, TokioRuntimeProvider::default())
        .with_signer(Some(Arc::new(signer)))
        .build();
    let (mut client, driver) = Client::connect(conn).await.expect("failed to connect");
    tokio::spawn(driver);

    // create a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let origin = Name::from_str("example.com.").unwrap();
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(
            record.name().clone(),
            record.dns_class(),
            record.record_type(),
        )
        .await
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = client
        .create(record.clone(), origin.clone())
        .await
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client.create(record, origin).await.expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

// #[test]
// fn test_update() {
//     // named_process();
// }

// #[test]
// fn test_delete() {
//     // named_process();
// }
