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
extern crate trust_dns;
extern crate trust_dns_compatibility;

use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use chrono::Duration;
use futures::Stream;
use openssl::rsa::Rsa;

use trust_dns::client::{Client, ClientConnection, SyncClient};
use trust_dns::udp::UdpClientConnection;
use trust_dns::op::ResponseCode;
use trust_dns::rr::{DNSClass, Name, Record, RData, RecordType};
use trust_dns::rr::dnssec::{Algorithm, Signer, KeyPair};
use trust_dns_compatibility::named_process;

#[test]
fn test_get() {
    let (process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = UdpClientConnection::new(socket).unwrap();
    let client = SyncClient::new(conn);

    let name = Name::parse("www.example.com.", None).unwrap();
    let result = client
        .query(&name, DNSClass::IN, RecordType::A)
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0].rr_type(), RecordType::A);

    let rdata = result.answers()[0].rdata();
    if let &RData::A(address) = rdata {
        assert_eq!(address, Ipv4Addr::new(127, 0, 0, 1));
    } else {
        assert!(false);
    }
}

fn create_sig0_ready_client<CC>(conn: CC) -> SyncClient
    where CC: ClientConnection,
          <CC as ClientConnection>::MessageStream: Stream<Item=Vec<u8>, Error=io::Error> + 'static

{
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
    let mut pem = File::open(format!("{}/../compatibility/tests/conf/Kupdate.example.com.+008+07134.pem",
                                 server_path))
            .expect("could not find pem file");

    let mut pem_buf = Vec::<u8>::new();
    pem.read_to_end(&mut pem_buf)
        .expect("failed to read pem");
    let rsa = Rsa::private_key_from_pem(&pem_buf).expect("something wrong with key from pem");
    let key = KeyPair::from_rsa(rsa).unwrap();

    let signer = Signer::new(Algorithm::RSASHA256,
                             key,
                             Name::with_labels(vec!["update".to_string(),
                                                    "example".to_string(),
                                                    "com".to_string()]),
                             Duration::max_value(),
                             true,
                             true);

    SyncClient::with_signer(conn, signer)
}

#[test]
#[ignore]
fn test_create() {
    let (process, port) = named_process();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let conn = UdpClientConnection::new(socket).unwrap();

    let client = create_sig0_ready_client(conn);
    let origin = Name::with_labels(vec!["example".to_string(), "com".to_string()]);

    // create a record
    let mut record = Record::with(Name::with_labels(vec!["new".to_string(),
                                                         "example".to_string(),
                                                         "com".to_string()]),
                                  RecordType::A,
                                  Duration::minutes(5).num_seconds() as u32);
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
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[test]
fn test_update() {
    // named_process();
}

#[test]
fn test_delete() {
    // named_process();
}