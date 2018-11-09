extern crate tokio;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_resolver;

use std::net::*;
use std::str::FromStr;

use tokio::runtime::current_thread::Runtime;

use trust_dns::op::Query;
use trust_dns::rr::{Name, RecordType};
use trust_dns_integration::mock_client::*;
use trust_dns_proto::error::{ProtoError, ProtoResult};
use trust_dns_proto::xfer::{DnsHandle, DnsResponse};
use trust_dns_resolver::config::*;
use trust_dns_resolver::name_server_pool::{ConnectionProvider, NameServer, NameServerPool};

#[derive(Clone)]
struct MockConnProvider {}

impl ConnectionProvider for MockConnProvider {
    type ConnHandle = MockClientHandle;

    fn new_connection(_: &NameServerConfig, _: &ResolverOpts) -> Self::ConnHandle {
        MockClientHandle::mock(vec![])
    }
}

type MockedNameServer = NameServer<MockClientHandle, MockConnProvider>;
type MockedNameServerPool = NameServerPool<MockClientHandle, MockConnProvider>;

#[cfg(test)]
fn mock_nameserver(messages: Vec<ProtoResult<DnsResponse>>) -> MockedNameServer {
    let client = MockClientHandle::mock(messages);

    NameServer::from_conn(
        NameServerConfig {
            socket_addr: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        },
        ResolverOpts::default(),
        client,
    )
}

#[cfg(test)]
fn mock_nameserver_pool(
    udp: Vec<MockedNameServer>,
    tcp: Vec<MockedNameServer>,
    _mdns: Option<MockedNameServer>,
) -> MockedNameServerPool {
    #[cfg(not(feature = "mdns"))]
    return NameServerPool::from_nameservers(&ResolverOpts::default(), udp, tcp);

    #[cfg(feature = "mdns")]
    return NameServerPool::from_nameservers(
        &ResolverOpts::default(),
        udp,
        tcp,
        _mdns.unwrap_or_else(|| mock_nameserver(vec![])),
    );
}

#[test]
fn test_datagram() {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));
    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);
    let tcp_message = message(query.clone(), vec![tcp_record], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)]);
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)]);

    let mut pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None);

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_datagram_stream_upgrade() {
    // lookup to UDP should return truncated message
    // then lookup on TCP

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));
    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let mut udp_message = message(query.clone(), vec![udp_record], vec![], vec![]);
    udp_message.as_mut().unwrap().set_truncated(true);

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)]);
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)]);

    let mut pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None);

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
fn test_datagram_fails_to_stream() {
    // lookup to UDP should fail
    // then lookup on TCP

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let udp_message: Result<DnsResponse, _> = Err(ProtoError::from("Forced Testing Error"));

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)]);
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)]);

    let mut pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None);

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
#[cfg(feature = "mdns")]
fn test_local_mdns() {
    // lookup to UDP should fail
    // then lookup on TCP

    let query = Query::query(Name::from_str("www.example.local.").unwrap(), RecordType::A);

    let tcp_message: Result<DnsResponse, _> = Err(ProtoError::from("Forced Testing Error"));
    let udp_message: Result<DnsResponse, _> = Err(ProtoError::from("Forced Testing Error"));
    let mdns_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let mdns_message = message(query.clone(), vec![mdns_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)]);
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)]);
    let mdns_nameserver = mock_nameserver(vec![mdns_message.map(Into::into)]);

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        Some(mdns_nameserver),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], mdns_record);
}
