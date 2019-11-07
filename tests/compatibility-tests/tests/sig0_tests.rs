// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate chrono;
extern crate env_logger;
extern crate futures;
extern crate openssl;
extern crate trust_dns_client;
extern crate trust_dns_compatibility;

use std::env;
use std::fs::File;
use std::io::Read;
#[cfg(not(feature = "none"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

#[cfg(not(feature = "none"))]
use chrono::Duration;
use openssl::rsa::Rsa;

#[cfg(not(feature = "none"))]
use trust_dns_client::client::Client;
use trust_dns_client::client::{ClientConnection, SyncClient};
#[cfg(not(feature = "none"))]
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::dnssec::{Algorithm, KeyPair, Signer};
use trust_dns_client::rr::rdata::key::{KeyUsage, KEY};
use trust_dns_client::rr::Name;
#[cfg(not(feature = "none"))]
use trust_dns_client::rr::{DNSClass, RData, Record, RecordType};
#[cfg(not(feature = "none"))]
use trust_dns_client::udp::UdpClientConnection;
#[cfg(not(feature = "none"))]
use trust_dns_compatibility::named_process;

#[cfg(not(feature = "none"))]
#[test]
#[allow(unused)]
fn test_get() {
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
    assert_eq!(result.answers()[0].rr_type(), RecordType::A);

    let rdata = result.answers()[0].rdata();
    if let RData::A(address) = rdata {
        assert_eq!(address, &Ipv4Addr::new(127, 0, 0, 1));
    } else {
        panic!("RData::A wasn't here");
    }
}

#[allow(unused)]
fn create_sig0_ready_client<CC>(conn: CC) -> SyncClient<CC>
where
    CC: ClientConnection,
{
    let server_path =
        env::var("TDNS_SERVER_SRC_ROOT").unwrap_or_else(|_| "../../crates/server".to_owned());
    let pem_path = format!(
        "{}/../../tests/compatibility-tests/tests/conf/Kupdate.example.com.+008+56935.pem",
        server_path
    );
    println!("loading pem from: {}", pem_path);
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

    let signer = Signer::sig0(sig0key, key, Name::from_str("update.example.com").unwrap());

    assert_eq!(signer.calculate_key_tag().unwrap(), 56935_u16);

    SyncClient::with_signer(conn, signer)
}

#[cfg(not(feature = "none"))]
#[test]
#[allow(unused)]
fn test_create() {
    let (process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = UdpClientConnection::new(socket).unwrap();

    let client = create_sig0_ready_client(conn);
    let origin = Name::from_str("example.com.").unwrap();

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com.").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
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
    let mut record = record;
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

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
