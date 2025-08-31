use hickory_client::client::Client;
use hickory_proto::DnsHandle;
use hickory_proto::op::{DnsRequest, Edns, Message, Query};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType, RrKey};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::FirstAnswer;
use hickory_server::Server;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneType};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;
use test_support::subscribe;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_truncation() {
    subscribe();

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let udp_socket = UdpSocket::bind(&addr).await.unwrap();

    let nameserver = udp_socket.local_addr().unwrap();
    println!("udp_socket on port: {nameserver}");

    // Create and start the server.
    let mut server = Server::new(new_large_catalog(128));
    server.register_socket(udp_socket);

    // Create the UDP client.
    let stream = UdpClientStream::builder(nameserver, TokioRuntimeProvider::new()).build();
    let (client, bg) = Client::<TokioRuntimeProvider>::connect(stream)
        .await
        .unwrap();

    // Run the client exchange in the background.
    tokio::spawn(bg);

    // Build the query.
    let max_payload = 512;
    let mut msg = Message::query();
    msg.add_query({
        let mut query = Query::query(large_name(), RecordType::A);
        query.set_query_class(DNSClass::IN);
        query
    })
    .set_recursion_desired(true)
    .set_edns({
        let mut edns = Edns::new();
        edns.set_max_payload(max_payload).set_version(0);
        edns
    });

    let result = client
        .send(DnsRequest::from(msg))
        .first_answer()
        .await
        .expect("query failed");

    assert!(result.truncated());
    assert_eq!(max_payload, result.max_payload());

    server.shutdown_gracefully().await.unwrap();
}

pub fn new_large_catalog(num_records: u32) -> Catalog {
    // Create a large record set.
    let name = large_name();
    let mut record_set = RecordSet::new(name.clone(), RecordType::A, 0);
    for i in 1..num_records + 1 {
        let ip = Ipv4Addr::from(i);
        let rdata = RData::A(A(ip));
        record_set.insert(Record::from_rdata(name.clone(), 86400, rdata), 0);
    }

    let mut soa_record_set = RecordSet::new(name.clone(), RecordType::SOA, 0);
    soa_record_set.insert(
        Record::from_rdata(
            name.clone(),
            86400,
            RData::SOA(SOA::new(
                n("sns.dns.icann.org."),
                n("noc.dns.icann.org."),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )),
        ),
        0,
    );

    let mut records = BTreeMap::new();
    records.insert(RrKey::new(name.clone().into(), RecordType::A), record_set);
    records.insert(
        RrKey::new(name.clone().into(), RecordType::SOA),
        soa_record_set,
    );
    let handler = InMemoryZoneHandler::<TokioRuntimeProvider>::new(
        name,
        records,
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    )
    .unwrap();

    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), vec![Arc::new(handler)]);
    catalog
}

const LARGE_NAME: &str = "large.com.";

fn large_name() -> Name {
    n(LARGE_NAME)
}

pub fn n<S: AsRef<str>>(name: S) -> Name {
    Name::from_str(name.as_ref()).unwrap()
}
