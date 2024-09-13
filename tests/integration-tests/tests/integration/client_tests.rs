use std::net::*;
use std::pin::Pin;
#[cfg(feature = "dnssec")]
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex};

use futures::Future;
use hickory_proto::runtime::TokioRuntimeProvider;
use test_support::subscribe;
#[cfg(feature = "dnssec")]
use time::Duration;

use hickory_client::client::Signer;
#[cfg(feature = "dnssec")]
use hickory_client::client::SyncDnssecClient;
#[allow(deprecated)]
use hickory_client::client::{Client, ClientConnection, SyncClient};
use hickory_client::error::ClientErrorKind;
use hickory_client::tcp::TcpClientConnection;
use hickory_client::udp::UdpClientConnection;
use hickory_integration::example_authority::create_example;
use hickory_integration::{NeverReturnsClientConnection, TestClientStream};
use hickory_proto::error::ProtoError;
#[cfg(feature = "dnssec")]
use hickory_proto::op::ResponseCode;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
#[cfg(feature = "dnssec")]
use hickory_proto::rr::Record;
use hickory_proto::rr::{rdata::A, DNSClass, Name, RData, RecordType};
use hickory_proto::xfer::{DnsMultiplexer, DnsMultiplexerConnect};
use hickory_server::authority::{Authority, Catalog};

pub struct TestClientConnection {
    catalog: Arc<StdMutex<Catalog>>,
}

impl TestClientConnection {
    pub fn new(catalog: Catalog) -> TestClientConnection {
        TestClientConnection {
            catalog: Arc::new(StdMutex::new(catalog)),
        }
    }
}

#[allow(clippy::type_complexity)]
impl ClientConnection for TestClientConnection {
    type Sender = DnsMultiplexer<TestClientStream, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        Pin<Box<dyn Future<Output = Result<TestClientStream, ProtoError>> + Send>>,
        TestClientStream,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (client_stream, handle) = TestClientStream::new(self.catalog.clone());

        DnsMultiplexer::new(Box::pin(client_stream), handle, signer)
    }
}

#[test]
#[allow(deprecated)]
fn test_query_nonet() {
    let authority = create_example();
    let mut catalog = Catalog::new();
    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

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
#[allow(deprecated)]
fn test_query_udp_edns() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncClient::new(conn);

    test_query_edns(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
fn test_query_tcp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncClient::new(conn);

    test_query(client);
}

#[allow(deprecated)]
fn test_query<CC>(client: SyncClient<CC>)
where
    CC: ClientConnection,
{
    let name = Name::from_ascii("WWW.example.com").unwrap();

    let response = client
        .query(&name, DNSClass::IN, RecordType::A)
        .expect("Query failed");

    println!("response records: {response:?}");
    assert!(response
        .queries()
        .first()
        .expect("expected query")
        .name()
        .eq_case(&name));

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.record_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(ref address) = *record.data() {
        assert_eq!(address, &A::new(93, 184, 215, 14))
    } else {
        panic!();
    }
}

fn test_query_edns<CC>(client: SyncClient<CC>)
where
    CC: ClientConnection,
{
    let name = Name::from_ascii("WWW.example.com").unwrap();
    let mut edns = Edns::new();
    // garbage subnet value, but lets check
    edns.options_mut()
        .insert(EdnsOption::Subnet("1.2.0.0/16".parse().unwrap()));

    // TODO: write builder
    let mut msg = Message::new();
    msg.add_query({
        let mut query = Query::query(name.clone(), RecordType::A);
        query.set_query_class(DNSClass::IN);
        query
    })
    .set_id(rand::random::<u16>())
    .set_message_type(MessageType::Query)
    .set_op_code(OpCode::Query)
    .set_recursion_desired(true)
    .set_edns(edns)
    .extensions_mut()
    .as_mut()
    .map(|edns| edns.set_max_payload(1232).set_version(0));

    let response = client.send(msg).remove(0).expect("Query failed");

    println!("response records: {response:?}");
    assert!(response
        .queries()
        .first()
        .expect("expected query")
        .name()
        .eq_case(&name));

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.record_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);
    assert!(response.extensions().is_some());
    assert_eq!(
        response
            .extensions()
            .as_ref()
            .unwrap()
            .option(EdnsCode::Subnet)
            .unwrap(),
        &EdnsOption::Subnet("1.2.0.0/16".parse().unwrap())
    );

    if let RData::A(ref address) = *record.data() {
        assert_eq!(address, &A::new(93, 184, 215, 14))
    } else {
        panic!();
    }
}

#[test]
#[ignore] // this getting finnicky responses with UDP
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_secure_query_example_udp() {
    subscribe();

    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncDnssecClient::new(conn).build();

    test_secure_query_example(client);
}

#[test]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_secure_query_example_tcp() {
    subscribe();

    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncDnssecClient::new(conn).build();

    test_secure_query_example(client);
}

#[cfg(feature = "dnssec")]
fn test_secure_query_example<CC>(client: SyncDnssecClient<CC>)
where
    CC: ClientConnection,
{
    subscribe();

    let name = Name::from_str("www.example.com").unwrap();

    let response = client
        .query(&name, DNSClass::IN, RecordType::A)
        .expect("Query failed");

    println!("response records: {response:?}");
    assert!(response
        .extensions()
        .as_ref()
        .expect("edns not here")
        .dnssec_ok());

    let record = &response.answers()[0];
    assert_eq!(record.name(), &name);
    assert_eq!(record.record_type(), RecordType::A);
    assert_eq!(record.dns_class(), DNSClass::IN);

    if let RData::A(ref address) = *record.data() {
        assert_eq!(address, &A::new(93, 184, 215, 14))
    } else {
        panic!();
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

    if let ClientErrorKind::Timeout = err.kind() {
    } else {
        panic!("expected timeout error")
    }
}

#[test]
fn test_timeout_query_nonet() {
    subscribe();
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
    let client = SyncClient::new(
        TcpClientConnection::with_timeout(
            addr,
            Duration::from_millis(1),
            TokioRuntimeProvider::new(),
        )
        .unwrap(),
    );
    test_timeout_query(client);
}

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_udp() {
//     let c = SyncDnssecClient::new(UdpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("rollernet.us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DS),
//     ).unwrap();
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_tcp() {
//     let c = SyncDnssecClient::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("rollernet.us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DS),
//     ).unwrap();
// }

// // TODO: this test is flaky
// #[test]
// #[ignore]
// #[allow(deprecated)]
// fn test_dnssec_rollernet_td_tcp_mixed_case() {
//     let c = SyncDnssecClient::new(TcpClientConnection::new("8.8.8.8:53".parse().unwrap()).unwrap())
//         .build();
//     c.secure_query(
//         &Name::parse("RollErnet.Us.", None).unwrap(),
//         DNSClass::IN,
//         RecordType::DS),
//     ).unwrap();
// }

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_nsec_query_example_udp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncDnssecClient::new(conn).build();
    test_nsec_query_example::<UdpClientConnection>(client);
}

#[test]
#[ignore]
#[allow(deprecated)]
#[cfg(feature = "dnssec")]
fn test_nsec_query_example_tcp() {
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncDnssecClient::new(conn).build();
    test_nsec_query_example::<TcpClientConnection<TokioRuntimeProvider>>(client);
}

#[cfg(feature = "dnssec")]
fn test_nsec_query_example<CC>(client: SyncDnssecClient<CC>)
where
    CC: ClientConnection,
{
    let name = Name::from_str("none.example.com").unwrap();

    let response = client
        .query(&name, DNSClass::IN, RecordType::A)
        .expect("Query failed");

    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[test]
#[ignore]
#[cfg(feature = "dnssec")]
fn test_nsec_query_type() {
    let name = Name::from_str("www.example.com").unwrap();

    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncDnssecClient::new(conn).build();

    let response = client
        .query(&name, DNSClass::IN, RecordType::NS)
        .expect("Query failed");

    // TODO: it would be nice to verify that the NSEC records were validated...
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(response.answers().is_empty());
}

// NSEC3 tests
#[test]
#[cfg(feature = "dnssec")]
fn test_nsec3_nxdomain() {
    let name = Name::from_labels(vec!["a", "b", "c", "example", "com"]).unwrap();

    let addr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncDnssecClient::new(conn).build();

    let response = client
        .query(&name, DNSClass::IN, RecordType::NS)
        .expect("Query failed");

    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[test]
#[cfg(feature = "dnssec")]
fn test_nsec3_no_data() {
    let name = Name::from_labels(vec!["www", "example", "com"]).unwrap();

    let addr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncDnssecClient::new(conn).build();

    let response = client
        .query(&name, DNSClass::IN, RecordType::PTR)
        .expect("Query failed");

    // the name "www.example.com" exists but there's no PTR record on it
    assert_eq!(response.response_code(), ResponseCode::NoError);
}

#[test]
#[cfg(feature = "dnssec")]
fn test_nsec3_query_name_is_soa_name() {
    let name = Name::from_labels("valid.extended-dns-errors.com".split(".")).unwrap();

    let addr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
    let client = SyncDnssecClient::new(conn).build();

    let response = client
        .query(&name, DNSClass::IN, RecordType::PTR)
        .expect("Query failed");

    // the name "valid.extended-dns-errors.com" exists but there's no PTR record on it
    assert_eq!(response.response_code(), ResponseCode::NoError);
}

// TODO: disabled until I decide what to do with NSEC3 see issue #10
//
// TODO these NSEC3 tests don't work, it seems that the zone is not signed properly.
// #[test]
// #[ignore]
// fn test_nsec3_sdsmt() {
//   let addr: SocketAddr = ("75.75.75.75",53).to_socket_addrs().unwrap().next().unwrap();
//   let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
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
//   let conn = TcpClientConnection::new(addr, TokioRuntimeProvider::new()).unwrap();
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
#[cfg(all(feature = "dnssec", feature = "sqlite"))]
fn create_sig0_ready_client(mut catalog: Catalog) -> (SyncClient<TestClientConnection>, Name) {
    use hickory_proto::rr::dnssec::rdata::{DNSSECRData, KEY};
    use hickory_proto::rr::dnssec::{Algorithm, KeyPair, Signer as SigSigner};
    use hickory_server::store::sqlite::SqliteAuthority;
    use openssl::rsa::Rsa;

    let authority = create_example();
    let mut authority = SqliteAuthority::new(authority, true, false);
    authority.set_allow_update(true);
    let origin = authority.origin().clone();

    let rsa = Rsa::generate(2_048).unwrap();
    let key = KeyPair::from_rsa(rsa).unwrap();

    let signer = SigSigner::new(
        Algorithm::RSASHA256,
        key,
        Name::from_str("trusted.example.com").unwrap(),
        // can be Duration::MAX after min Rust version 1.53
        std::time::Duration::new(u64::MAX, 1_000_000_000 - 1),
        true,
        true,
    );

    // insert the KEY for the trusted.example.com
    let auth_key = Record::from_rdata(
        Name::from_str("trusted.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::DNSSEC(DNSSECRData::KEY(KEY::new(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            signer.algorithm(),
            signer.key().to_public_bytes().expect("to_vec failed"),
        ))),
    );
    authority.upsert_mut(auth_key, 0);

    catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);
    let client = SyncClient::with_signer(TestClientConnection::new(catalog), signer);

    (client, origin.into())
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_create() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // create a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
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

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_append() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

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
        .query(record.name(), record.dns_class(), record.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert_eq!(result.answers()[0], record);

    // will fail if already set and not the same value.
    record.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);

    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = *rr.data() {
            ip == A::new(100, 10, 100, 10)
        } else {
            false
        }));
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(101, 11, 101, 11)
        } else {
            false
        }));

    // show that appending the same thing again is ok, but doesn't add any records
    let result = client
        .append(record.clone(), origin, true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 2);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_compare_and_swap() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // create a record
    let record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let current = record;
    let mut new = current.clone();
    new.set_data(RData::A(A::new(101, 11, 101, 11)));

    let result = client
        .compare_and_swap(current.clone(), new.clone(), origin.clone())
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(new.name(), new.dns_class(), new.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(101, 11, 101, 11)
        } else {
            false
        }));

    // check the it fails if tried again.
    new.set_data(RData::A(A::new(102, 12, 102, 12)));

    let result = client
        .compare_and_swap(current, new.clone(), origin)
        .expect("compare_and_swap failed");
    assert_eq!(result.response_code(), ResponseCode::NXRRSet);

    let result = client
        .query(new.name(), new.dns_class(), new.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(101, 11, 101, 11)
        } else {
            false
        }));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_by_rdata() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

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

    record.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_by_rdata(record.clone(), origin)
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);
    assert_eq!(result.answers().len(), 1);
    assert!(result
        .answers()
        .iter()
        .any(|rr| if let RData::A(ip) = rr.data() {
            *ip == A::new(100, 10, 100, 10)
        } else {
            false
        }));
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_rrset() {
    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

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

    record.set_data(RData::A(A::new(101, 11, 101, 11)));
    let result = client
        .append(record.clone(), origin.clone(), true)
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_rrset(record.clone(), origin)
        .expect("delete failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    let result = client
        .query(record.name(), record.dns_class(), record.record_type())
        .expect("query failed");
    assert_eq!(result.response_code(), ResponseCode::NXDomain);
    assert_eq!(result.answers().len(), 0);
}

#[cfg(all(feature = "dnssec", feature = "sqlite"))]
#[test]
fn test_delete_all() {
    use hickory_proto::rr::rdata::AAAA;

    let catalog = Catalog::new();
    let (client, origin) = create_sig0_ready_client(catalog);

    // append a record
    let mut record = Record::from_rdata(
        Name::from_str("new.example.com").unwrap(),
        Duration::minutes(5).whole_seconds() as u32,
        RData::A(A::new(100, 10, 100, 10)),
    );

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

    record.set_data(RData::AAAA(AAAA::new(1, 2, 3, 4, 5, 6, 7, 8)));
    let result = client
        .create(record.clone(), origin.clone())
        .expect("create failed");
    assert_eq!(result.response_code(), ResponseCode::NoError);

    // verify record contents
    let result = client
        .delete_all(record.name().clone(), origin, DNSClass::IN)
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
