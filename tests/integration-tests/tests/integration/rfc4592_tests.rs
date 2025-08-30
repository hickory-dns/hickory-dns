//! These tests exercise handling of wildcards in zones.
//!
//! They are based on the example zone and responses in [RFC 4592 section
//! 2.2.1](https://datatracker.ietf.org/doc/html/rfc4592#section-2.2.1).

use std::{net::Ipv4Addr, sync::Arc};

use hickory_client::client::{Client, ClientHandle};
use hickory_integration::print_response;
use hickory_proto::{
    op::ResponseCode,
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, MX, NS, SOA, SRV, TXT},
    },
    runtime::TokioRuntimeProvider,
    udp::UdpClientStream,
};
use hickory_resolver::Name;
use hickory_server::{
    Server,
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneType},
};
use test_support::subscribe;
use tokio::net::UdpSocket;

/// ```text
/// The following responses would be synthesized from one of the
/// wildcards in the zone:
///
///    QNAME=host3.example. QTYPE=MX, QCLASS=IN
///         the answer will be a "host3.example. IN MX ..."
/// ```
#[tokio::test]
async fn wildcard_synthesis_1() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("host3.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(
        response
            .answers()
            .iter()
            .any(|record| record.record_type() == query_type && record.name() == &query_name)
    );
}

/// ```text
/// The following responses would be synthesized from one of the
/// wildcards in the zone:
///
///    QNAME=host3.example. QTYPE=A, QCLASS=IN
///         the answer will reflect "no error, but no data"
///         because there is no A RR set at '*.example.'
/// ```
#[tokio::test]
#[ignore = "hickory only checks for one record type during wildcard synthesis (issue #2905)"]
async fn wildcard_synthesis_2() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("host3.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers(), []);
}

/// ```text
/// The following responses would be synthesized from one of the
/// wildcards in the zone:
///
///    QNAME=foo.bar.example. QTYPE=TXT, QCLASS=IN
///         the answer will be "foo.bar.example. IN TXT ..."
///         because bar.example. does not exist, but the wildcard
///         does.
/// ```
#[tokio::test]
async fn wildcard_synthesis_3() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("foo.bar.example.", None).unwrap();
    let query_type = RecordType::TXT;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(
        response
            .answers()
            .iter()
            .any(|record| record.record_type() == query_type && record.name() == &query_name)
    );
}

/// ```text
/// The following responses would not be synthesized from any of the
/// wildcards in the zone:
///
///    QNAME=host1.example., QTYPE=MX, QCLASS=IN
///         because host1.example. exists
/// ```
#[tokio::test]
#[ignore = "hickory does not check for blocking names"]
async fn no_synthesis_1() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("host1.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers(), []);
}

/// ```text
/// The following responses would not be synthesized from any of the
/// wildcards in the zone:
///
///    QNAME=sub.*.example., QTYPE=MX, QCLASS=IN
///         because sub.*.example. exists
/// ```
#[ignore = "hickory does not check for blocking names"]
#[tokio::test]
async fn no_synthesis_2() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("sub.*.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers(), []);
}

/// ```text
/// The following responses would not be synthesized from any of the
/// wildcards in the zone:
///
///    QNAME=_telnet._tcp.host1.example., QTYPE=SRV, QCLASS=IN
///         because _tcp.host1.example. exists (without data)
/// ```
#[tokio::test]
async fn no_synthesis_3() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("_telnet._tcp.host1.example.", None).unwrap();
    let query_type = RecordType::SRV;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
    assert_eq!(response.answers(), []);
}

/// ```text
/// The following responses would not be synthesized from any of the
/// wildcards in the zone:
///
///    QNAME=host.subdel.example., QTYPE=A, QCLASS=IN
///         because subdel.example. exists (and is a zone cut)
/// ```
#[ignore = "hickory does not send referrals for names below delegation points (issue #2810)"]
#[tokio::test]
async fn no_synthesis_4() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("host.subdel.example.", None).unwrap();
    let query_type = RecordType::A;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers(), []);
    let delegation_name = query_name.base_name();
    assert!(
        response
            .authorities()
            .iter()
            .any(|record| record.record_type() == RecordType::NS
                && record.name() == &delegation_name)
    );
}

/// ```text
/// The following responses would not be synthesized from any of the
/// wildcards in the zone:
///
///    QNAME=ghost.*.example., QTYPE=MX, QCLASS=IN
///         because *.example. exists
/// ```
#[tokio::test]
#[ignore = "hickory does not treat wildcards as blocking themselves"]
async fn no_synthesis_5() {
    subscribe();

    let (mut client, _server) = setup().await;

    let query_name = Name::parse("ghost.*.example.", None).unwrap();
    let query_type = RecordType::MX;
    let response = client
        .query(query_name.clone(), DNSClass::IN, query_type)
        .await
        .unwrap();
    print_response(&response);
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
    assert_eq!(response.answers(), []);
}

/// ```text
/// $ORIGIN example.
/// example.                 3600 IN  SOA   <SOA RDATA>
/// example.                 3600     NS    ns.example.com.
/// example.                 3600     NS    ns.example.net.
/// *.example.               3600     TXT   "this is a wildcard"
/// *.example.               3600     MX    10 host1.example.
/// sub.*.example.           3600     TXT   "this is not a wildcard"
/// host1.example.           3600     A     192.0.2.1
/// _ssh._tcp.host1.example. 3600     SRV   <SRV RDATA>
/// _ssh._tcp.host2.example. 3600     SRV   <SRV RDATA>
/// subdel.example.          3600     NS    ns.example.com.
/// subdel.example.          3600     NS    ns.example.net.
/// ```
async fn setup() -> (Client<TokioRuntimeProvider>, Server<Catalog>) {
    // Zone setup
    let origin = Name::parse("example.", None).unwrap();

    const SERIAL: u32 = 1;
    const TTL: u32 = 3600;

    let mut handler = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        None,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::SOA(SOA::new(
                Name::parse("mname", Some(&origin)).unwrap(),
                Name::parse("rname", Some(&origin)).unwrap(),
                SERIAL,
                3600,
                300,
                3600000,
                TTL,
            )),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::NS(NS(Name::parse("ns.example.com.", None).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            origin.clone(),
            TTL,
            RData::NS(NS(Name::parse("ns.example.net.", None).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("*", Some(&origin)).unwrap(),
            TTL,
            RData::TXT(TXT::new(vec!["this is a wildcard".to_string()])),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("*", Some(&origin)).unwrap(),
            TTL,
            RData::MX(MX::new(10, Name::parse("host1", Some(&origin)).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("sub.*", Some(&origin)).unwrap(),
            TTL,
            RData::TXT(TXT::new(vec!["this is not a wildcard".to_string()])),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("host1", Some(&origin)).unwrap(),
            TTL,
            RData::A(A::new(192, 0, 2, 1)),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("_ssh._tcp.host1", Some(&origin)).unwrap(),
            TTL,
            RData::SRV(SRV::new(
                0,
                0,
                22,
                Name::parse("ssh.example.com.", None).unwrap(),
            )),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("_ssh._tcp.host2", Some(&origin)).unwrap(),
            TTL,
            RData::SRV(SRV::new(
                0,
                0,
                22,
                Name::parse("ssh.example.net.", None).unwrap(),
            )),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("subdel", Some(&origin)).unwrap(),
            TTL,
            RData::NS(NS(Name::parse("ns.example.com.", None).unwrap())),
        ),
        SERIAL,
    );
    handler.upsert_mut(
        Record::from_rdata(
            Name::parse("subdel", Some(&origin)).unwrap(),
            TTL,
            RData::NS(NS(Name::parse("ns.example.net.", None).unwrap())),
        ),
        SERIAL,
    );

    let mut catalog = Catalog::new();
    catalog.upsert(origin.into(), vec![Arc::new(handler)]);

    // Server setup
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut server = Server::new(catalog);
    server.register_socket(udp_socket);

    // Client setup
    let stream = UdpClientStream::builder(local_addr, TokioRuntimeProvider::new()).build();
    let (client, bg) = Client::connect(stream).await.unwrap();
    tokio::spawn(bg);

    (client, server)
}
