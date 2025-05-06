// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(not(feature = "none"))]

use std::env;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use futures::TryStreamExt;
use time::Duration;

use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_client::proto::dnssec::tsig::TSigner;
use hickory_client::proto::op::{MessageSigner, ResponseCode};
use hickory_client::proto::rr::{Name, RData, Record, rdata::A};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::xfer::DnsMultiplexer;
use hickory_compatibility::named_process;
use test_support::subscribe;

fn signer() -> Arc<dyn MessageSigner> {
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    let pem_path = format!("{server_path}/tests/compatibility-tests/tests/conf/tsig.raw");
    println!("loading key from: {pem_path}");
    let mut key_file = File::open(pem_path).expect("could not find key file");

    let mut key = Vec::new();
    key_file
        .read_to_end(&mut key)
        .expect("error reading key file");

    let key_name = Name::from_ascii("tsig-key.").unwrap();
    Arc::new(TSigner::new(key, TsigAlgorithm::HmacSha512, key_name, 60).unwrap())
}

#[tokio::test]
async fn test_create() {
    subscribe();

    let (_process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = UdpClientStream::builder(socket, TokioRuntimeProvider::default())
        .with_signer(Some(signer()))
        .build();
    let (mut client, driver) = Client::connect(stream).await.expect("failed to connect");
    tokio::spawn(driver);

    // create a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.net.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let origin = Name::from_str("example.net.").unwrap();
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

#[tokio::test]
async fn test_tsig_zone_transfer() {
    subscribe();

    let (_process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let (stream, sender) =
        TcpClientStream::new(socket, None, None, TokioRuntimeProvider::default());
    let multiplexer = DnsMultiplexer::new(stream, sender, Some(signer()));

    let (mut client, driver) = Client::connect(multiplexer)
        .await
        .expect("failed to connect");
    tokio::spawn(driver);

    let name = Name::from_str("example.net.").unwrap();
    let result = client
        .zone_transfer(name.clone(), None)
        .try_collect::<Vec<_>>()
        .await
        .expect("query failed");
    assert_ne!(result.len(), 1);
    assert_eq!(
        result.iter().map(|r| r.answers().len()).sum::<usize>(),
        2000 + 3
    );
}
