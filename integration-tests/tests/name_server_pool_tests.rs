extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_resolver;

use std::net::*;
use std::str::FromStr;

use tokio_core::reactor::{Core, Handle};

use trust_dns::op::Query;
use trust_dns::rr::{Name, RecordType};
use trust_dns_integration::mock_client::*;
use trust_dns_proto::xfer::{DnsHandle, DnsRequest, DnsResponse};
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::*;
use trust_dns_resolver::name_server_pool::{ConnectionProvider, NameServer, NameServerPool};

#[derive(Clone)]
struct MockConnProvider {}

impl ConnectionProvider for MockConnProvider {
    type ConnHandle = MockClientHandle<ResolveError>;

    fn new_connection(_: &NameServerConfig, _: &ResolverOpts, _: &Handle) -> Self::ConnHandle {
        MockClientHandle::mock(vec![])
    }
}

type MockedNameServer = NameServer<MockClientHandle<ResolveError>, MockConnProvider>;
type MockedNameServerPool = NameServerPool<MockClientHandle<ResolveError>, MockConnProvider>;

#[cfg(test)]
fn mock_nameserver(
    messages: Vec<ResolveResult<DnsResponse>>,
    reactor: &Handle,
) -> MockedNameServer {
    let client = MockClientHandle::mock(messages);

    NameServer::from_conn(
        NameServerConfig {
            socket_addr: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        },
        ResolverOpts::default(),
        client,
        reactor,
    )
}

#[cfg(test)]
fn mock_nameserver_pool(
    udp: Vec<MockedNameServer>,
    tcp: Vec<MockedNameServer>,
    _mdns: Option<MockedNameServer>,
    _reactor: &Handle,
) -> MockedNameServerPool {
    #[cfg(not(feature = "mdns"))]
    return NameServerPool::from_nameservers(&ResolverOpts::default(), udp, tcp);

    #[cfg(feature = "mdns")]
    return NameServerPool::from_nameservers(
        &ResolverOpts::default(),
        udp,
        tcp,
        _mdns.unwrap_or_else(|| mock_nameserver(vec![], _reactor)),
    );
}

#[test]
fn test_datagram() {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));
    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);
    let tcp_message = message(query.clone(), vec![tcp_record], vec![], vec![]);

    let mut reactor = Core::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], &reactor.handle());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], &reactor.handle());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        &reactor.handle(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message::<ResolveError>(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(DnsRequest::from(request.into()));

    let response = reactor.run(future).unwrap();
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

    let mut reactor = Core::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], &reactor.handle());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], &reactor.handle());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        &reactor.handle(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message::<ResolveError>(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.run(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
fn test_datagram_fails_to_stream() {
    // lookup to UDP should fail
    // then lookup on TCP

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let udp_message: Result<DnsResponse, _> =
        Err(ResolveErrorKind::Msg(format!("Forced Testing Error")).into());

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let mut reactor = Core::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], &reactor.handle());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], &reactor.handle());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        &reactor.handle(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message::<ResolveError>(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.run(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
#[cfg(feature = "mdns")]
fn test_local_mdns() {
    // lookup to UDP should fail
    // then lookup on TCP

    let query = Query::query(Name::from_str("www.example.local.").unwrap(), RecordType::A);

    let tcp_message: Result<DnsResponse, _> =
        Err(ResolveErrorKind::Msg(format!("Forced Testing Error")).into());
    let udp_message: Result<DnsResponse, _> =
        Err(ResolveErrorKind::Msg(format!("Forced Testing Error")).into());
    let mdns_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let mdns_message = message(query.clone(), vec![mdns_record.clone()], vec![], vec![]);

    let mut reactor = Core::new().unwrap();

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], &reactor.handle());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], &reactor.handle());
    let mdns_nameserver = mock_nameserver(vec![mdns_message.map(Into::into)], &reactor.handle());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        Some(mdns_nameserver),
        &reactor.handle(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message::<ResolveError>(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.run(future).unwrap();
    assert_eq!(response.answers()[0], mdns_record);
}
