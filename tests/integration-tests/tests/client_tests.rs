extern crate chrono;
extern crate env_logger;
extern crate futures;
extern crate openssl;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_rustls;
extern crate trust_dns_server;

use std::net::*;
#[cfg(feature = "dnssec")]
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[cfg(feature = "dnssec")]
use chrono::Duration;
use futures::Future;

#[cfg(feature = "dnssec")]
use trust_dns::client::SecureSyncClient;
#[allow(deprecated)]
use trust_dns::client::{Client, ClientConnection, SyncClient};
use trust_dns::error::ClientErrorKind;
use trust_dns::rr::dnssec::Signer;
#[cfg(feature = "dnssec")]
use trust_dns::rr::Record;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::tcp::TcpClientConnection;
use trust_dns::udp::UdpClientConnection;
use trust_dns_integration::authority::create_example;
use trust_dns_integration::{NeverReturnsClientConnection, TestClientStream};
use trust_dns_proto::error::ProtoError;
#[cfg(feature = "dnssec")]
use trust_dns_proto::op::*;
use trust_dns_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect, DnsRequestSender};
use trust_dns_server::authority::{Authority, Catalog};

pub struct TestClientConnection {
    catalog: Arc<Mutex<Catalog>>,
}

impl TestClientConnection {
    pub fn new(catalog: Catalog) -> TestClientConnection {
        TestClientConnection {
            catalog: Arc::new(Mutex::new(catalog)),
        }
    }
}

impl ClientConnection for TestClientConnection {
    type Sender = DnsMultiplexer<TestClientStream, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<
        Box<Future<Item = TestClientStream, Error = ProtoError> + Send>,
        TestClientStream,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (client_stream, handle) = TestClientStream::new(self.catalog.clone());

        DnsMultiplexer::new(Box::new(client_stream), Box::new(handle), signer)
    }
}

#[test]
#[allow(deprecated)]
fn test_query_nonet() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), Box::new(authority));

    let client = SyncClient::new(TestClientConnection::new(catalog));

    test_query(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_query_udp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncClient::new(conn);

    test_query(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_query_tcp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let client = SyncClient::new(conn);

    test_query(client);
}

#[allow(deprecated)]
fn test_query<CC>(client: SyncClient<CC>)
where
    CC: ClientConnection,
{
    let name = Name::from_ascii("WWW.example.com").unwrap();

    let response = client.query(&name, DNSClass::IN, RecordType::A);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();

    println!("response records: {:?}", response);
    assert!(
        response
            .queries()
            .first()
            .expect("expected query")
            .name()
            .eq_case(&name)
    );

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.rr_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(ref address) = *record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
    } else {
        assert!(false);
    }
}

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_secure_query_example_udp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SecureSyncClient::new(conn).build();

    test_secure_query_example(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_secure_query_example_tcp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let client = SecureSyncClient::new(conn).build();

    test_secure_query_example(client);
}

#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_secure_query_example<CC>(client: SecureSyncClient<CC>)
where
    CC: ClientConnection,
{
    // extern crate env_logger;
    // env_logger::try_init().ok();

    let name = Name::from_str("www.example.com").unwrap();
    let response = client.secure_query(&name, DNSClass::IN, RecordType::A);

    assert!(
        response.is_ok(),
        "query for {} failed: {}",
        name,
        response.unwrap_err()
    );

    let response = response.unwrap();

    println!("response records: {:?}", response);
    assert!(response.edns().expect("edns not here").dnssec_ok());

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.rr_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(ref address) = *record.rdata() {
        assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
    } else {
        assert!(false);
    }
}

fn test_timeout_query<CC>(client: SyncClient<CC>)
where
    CC: ClientConnection,
{
    let name = Name::from_ascii("WWW.example.com").unwrap();

    let response = client.query(&name, DNSClass::IN, RecordType::A);
    assert!(response.is_err());

    let err = response.unwrap_err();

    assert_eq!(err.kind(), &ClientErrorKind::Timeout);
}

#[test]
fn test_timeout_query_nonet() {
    env_logger::try_init().ok();
    // TODO: need to add timeout length to SyncClient
    let client = SyncClient::new(NeverReturnsClientConnection::new().unwrap());
    test_timeout_query(client);
}

#[test]
fn test_timeout_query_udp() {
    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    // TODO: need to add timeout length to SyncClient
    let client = SyncClient::new(UdpClientConnection::new(addr).unwrap());
    test_timeout_query(client);
}

#[test]
fn test_timeout_query_tcp() {
    use std::time::Duration;

    let addr: SocketAddr = ("203.0.113.0", 53)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    // TODO: need to add timeout length to SyncClient
    let client =
        SyncClient::new(TcpClientConnection::with_timeout(addr, Duration::from_millis(1)).unwrap());
    test_timeout_query(client);
}

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_udp() {
//     let c = SecureSyncClient::new(UdpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("rollernet.us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DNSSEC(DNSSECRecordType::DS),
//     ).unwrap();
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_tcp() {
//     let c = SecureSyncClient::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("rollernet.us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DNSSEC(DNSSECRecordType::DS),
//     ).unwrap();
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_tcp_mixed_case() {
//     let c = SecureSyncClient::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("RollErnet.Us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DNSSEC(DNSSECRecordType::DS),
//     ).unwrap();
// }

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_nsec_query_example_udp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SecureSyncClient::new(conn).build();
    test_nsec_query_example::<UdpClientConnection>(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_nsec_query_example_tcp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let client = SecureSyncClient::new(conn).build();
    test_nsec_query_example::<TcpClientConnection>(client);
}

#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_nsec_query_example<CC>(client: SecureSyncClient<CC>)
where
    CC: ClientConnection,
{
    let name = Name::from_str("none.example.com").unwrap();

    let response = client.secure_query(&name, DNSClass::IN, RecordType::A);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_nsec_query_type() {
    let name = Name::from_str("www.example.com").unwrap();

    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr).unwrap();
    let client = SecureSyncClient::new(conn).build();

    let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
    assert!(response.is_ok(), "query failed: {}", response.unwrap_err());

    let response = response.unwrap();
    // TODO: it would be nice to verify that the NSEC records were validated...
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());
}

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// TODO these NSEC3 tests don't work, it seems that the zone is not signed properly.
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr).unwrap();
//   let name = Name::from_labels(vec!["none", "sdsmt", "edu"]);
//   let client = Client::new(conn);
//
//   let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
//   assert!(response.is_ok(), "query failed: {}", response.unwrap_err());
//
//   let response = response.unwrap();
//   assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
// }

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt_type() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr).unwrap();
//   let name = Name::from_labels(vec!["www", "sdsmt", "edu"]);
//   let client = Client::new(conn);
//
//   let response = client.secure_query(&name, DNSClass::IN, RecordType::NS);
//   assert!(response.is_ok(), "query failed: {}", response.unwrap_err());
//
//   let response = response.unwrap();
//   assert_eq!(response.get_response_code(), ResponseCode::NXDomain);
// }

#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn create_sig0_ready_client(mut catalog: Catalog) -> (SyncClient<TestClientConnection>, Name) {
    use openssl::rsa::Rsa;
    use trust_dns::rr::dnssec::{Algorithm, KeyPair};
    use trust_dns_proto::rr::dnssec::rdata::{DNSSECRData, DNSSECRecordType, KEY};

    let mut authority = create_example();
    authority.set_allow_update(true);
    let origin = authority.origin().clone();

    let rsa = Rsa::generate(2048).unwrap();
    let key = KeyPair::from_rsa(rsa).unwrap();

    let signer = Signer::new(
        Algorithm::RSASHA256,
        key,
        Name::from_str("trusted.example.com").unwrap(),
        Duration::max_value(),
        true,
        true,
    );

    // insert the KEY for the trusted.example.com
    let mut auth_key = Record::with(
        Name::from_str("trusted.example.com").unwrap(),
        RecordType::DNSSEC(DNSSECRecordType::KEY),
        Duration::minutes(5).num_seconds() as u32,
    );
    auth_key.set_rdata(RData::DNSSEC(DNSSECRData::KEY(KEY::new(
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        signer.algorithm(),
        signer.key().to_public_bytes().expect("to_vec failed"),
    ))));
    authority.upsert(auth_key, 0);

    catalog.upsert(authority.origin().clone(), Box::new(authority));
    let client = SyncClient::with_signer(TestClientConnection::new(catalog), signer);

    (client, origin.into())
}

#[cfg(feature = "dnssec")]
#[test]
fn test_create() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
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
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::YXRRSet);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_append() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    // next append to a non-existent RRset
    let result = client
        .append(record.clone(), origin.clone(), false)
        .expect("append failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(
        result
            .answers()
            .iter()
            .any(|rr| if let RData::A(ip) = *rr.rdata() {
                ip == Ipv4Addr::new(100, 10, 100, 10)
            } else {
                false
            })
    );
    assert!(
        result
            .answers()
            .iter()
            .any(|rr| if let RData::A(ip) = rr.rdata() {
                *ip == Ipv4Addr::new(101, 11, 101, 11)
            } else {
                false
            })
    );

    // show that appending the same thing again is ok, but doesn't add any records
    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_compare_and_swap() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // create a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

    let result = client
        .compare_and_swap(current.clone(), new.clone(), origin.clone())
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(new.name(), new.dns_class(), new.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(
        result
            .answers()
            .iter()
            .any(|rr| if let RData::A(ip) = rr.rdata() {
                *ip == Ipv4Addr::new(101, 11, 101, 11)
            } else {
                false
            })
    );

    // check the it fails if tried again.
    let mut new = new;
    new.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));

    let result = client
        .compare_and_swap(current, new.clone(), origin.clone())
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = client
        .query(new.name(), new.dns_class(), new.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(
        result
            .answers()
            .iter()
            .any(|rr| if let RData::A(ip) = rr.rdata() {
                *ip == Ipv4Addr::new(101, 11, 101, 11)
            } else {
                false
            })
    );
}

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_by_rdata() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = client
        .delete_by_rdata(record.clone(), origin.clone())
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_by_rdata(record.clone(), origin.clone())
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(
        result
            .answers()
            .iter()
            .any(|rr| if let RData::A(ip) = rr.rdata() {
                *ip == Ipv4Addr::new(100, 10, 100, 10)
            } else {
                false
            })
    );
}

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_rrset() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = client
        .delete_rrset(record.clone(), origin.clone())
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_rrset(record.clone(), origin.clone())
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.rr_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_delete_all() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::with(
        Name::from_str("new.example.com").unwrap(),
        RecordType::A,
        Duration::minutes(5).num_seconds() as u32,
    );
    record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

    // first check the must_exist option
    let result = client
        .delete_all(record.name().clone(), origin.clone(), DNSClass::IN)
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // next create to a non-existent RRset
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let mut record = record.clone();
    record.set_rr_type(RecordType::AAAA);
    record.set_rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_all(record.name().clone(), origin.clone(), DNSClass::IN)
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), RecordType::A)
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);

    let result = client
        .query(record.name(), record.dns_class(), RecordType::AAAA)
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}
