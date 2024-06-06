// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;
use std::fs::File;
use std::io::Read;
#[cfg(not(feature = "none"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use openssl::rsa::Rsa;
#[cfg(not(feature = "none"))]
use time::Duration;

#[cfg(not(feature = "none"))]
use hickory_client::client::Client;
use hickory_client::client::{ClientConnection, SyncClient};
#[cfg(not(feature = "none"))]
use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::dnssec::rdata::key::{KeyUsage, KEY};
use hickory_client::proto::rr::dnssec::{Algorithm, KeyPair, SigSigner};
use hickory_client::proto::rr::Name;
#[cfg(not(feature = "none"))]
use hickory_client::proto::rr::{DNSClass, RData, Record, RecordType};
#[cfg(not(feature = "none"))]
use hickory_client::udp::UdpClientConnection;
#[cfg(not(feature = "none"))]
use hickory_compatibility::named_process;

#[cfg(not(feature = "none"))]
#[test]
#[allow(unused)]
fn test_get() {
    use hickory_client::rr::rdata::A;

    let (process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = UdpClientConnection::new(socket).unwrap();
    let client = SyncClient::new(conn);

    let name = Name::from_str("www.example.com.").unwrap();
    let result = client
        .query(&name, DNSClass::IN, RecordType::A)
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

#[allow(unused)]
fn create_sig0_ready_client<CC>(conn: CC) -> SyncClient<CC>
where
    CC: ClientConnection,
{
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    let pem_path = format!(
        "{server_path}/tests/compatibility-tests/tests/conf/Kupdate.example.com.+008+56935.pem"
    );
    println!("loading pem from: {pem_path}");
    let mut pem = File::open(pem_path).expect("could not find pem file");

    let mut pem_buf = Vec::<u8>::new();
    pem.read_to_end(&mut pem_buf).expect("failed to read pem");
    let rsa = Rsa::private_key_from_pem(&pem_buf).expect("something wrong with key from pem");
    let key = KeyPair::from_rsa(rsa).unwrap();
    let sig0key = KEY::new(
        Default::default(),
        KeyUsage::Entity,
        Default::default(),
        Default::default(),
        Algorithm::RSASHA256,
        key.to_public_bytes().unwrap(),
    );

    let signer = SigSigner::sig0(sig0key, key, Name::from_str("update.example.com").unwrap());

    assert_eq!(signer.calculate_key_tag().unwrap(), 56935_u16);

    SyncClient::with_signer(conn, signer)
}

#[cfg(not(feature = "none"))]
#[test]
#[allow(unused)]
fn test_create() {
    use hickory_client::rr::rdata::A;

    let (process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = UdpClientConnection::new(socket).unwrap();

    let client = create_sig0_ready_client(conn);
    let origin = Name::from_str("example.com.").unwrap();

    // create a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com.").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(record.name(), record.dns_class(), record.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // trying to create again should error
    // TODO: it would be cool to make this
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);

    // will fail if already set and not the same value.
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client.create(record, origin).expect("create failed");
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
