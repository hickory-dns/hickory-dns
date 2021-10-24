// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(unused_imports)]

use std::env;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use time::Duration;

use trust_dns_client::client::Client;
use trust_dns_client::client::{ClientConnection, SyncClient};
use trust_dns_client::op::ResponseCode;
use trust_dns_client::proto::rr::dnssec::rdata::tsig::TsigAlgorithm;
use trust_dns_client::rr::dnssec::tsig::TSigner;
use trust_dns_client::rr::Name;
use trust_dns_client::rr::{RData, Record, RecordType};
use trust_dns_client::tcp::TcpClientConnection;
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_compatibility::named_process;

#[allow(dead_code)]
pub fn create_tsig_ready_client<CC>(conn: CC) -> SyncClient<CC>
where
    CC: ClientConnection,
{
    let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    let pem_path = format!(
        "{}/tests/compatibility-tests/tests/conf/tsig.raw",
        server_path
    );
    println!("loading key from: {}", pem_path);
    let mut key_file = File::open(pem_path).expect("could not find key file");

    let mut key = Vec::new();
    key_file
        .read_to_end(&mut key)
        .expect("error reading key file");

    let key_name = Name::from_ascii("tsig-key").unwrap();
    let signer = TSigner::new(key, TsigAlgorithm::HmacSha512, key_name, 60).unwrap();

    SyncClient::with_tsigner(conn, signer)
}

#[cfg(not(feature = "none"))]
#[test]
fn test_create() {
    let (_process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = UdpClientConnection::new(socket).unwrap();

    let client = create_tsig_ready_client(conn);
    let origin = Name::from_str("example.net.").unwrap();

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.net.").unwrap(),
        RecordType::A,
        Duration::minutes(5).whole_seconds() as u32,
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

#[cfg(not(feature = "none"))]
#[test]
fn test_tsig_zone_transfer() {
    let (_process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = TcpClientConnection::new(socket).unwrap();

    let client = create_tsig_ready_client(conn);

    let name = Name::from_str("example.net.").unwrap();
    let result = client.zone_transfer(&name, None).expect("query failed");
    let result = result.collect::<Result<Vec<_>, _>>().unwrap();
    assert_ne!(result.len(), 1);
    assert_eq!(
        result.iter().map(|r| r.answers().len()).sum::<usize>(),
        2000 + 3
    );
}
