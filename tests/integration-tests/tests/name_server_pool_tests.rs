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
fn mock_nameserver(
    messages: Vec<ProtoResult<DnsResponse>>,
    options: ResolverOpts,
) -> MockedNameServer {
    let client = MockClientHandle::mock(messages);

    NameServer::from_conn(
        NameServerConfig {
            socket_addr: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        },
        options,
        client,
    )
}

#[cfg(test)]
fn mock_nameserver_pool(
    udp: Vec<MockedNameServer>,
    tcp: Vec<MockedNameServer>,
    _mdns: Option<MockedNameServer>,
    options: ResolverOpts,
) -> MockedNameServerPool {
    #[cfg(not(feature = "mdns"))]
    return NameServerPool::from_nameservers(&options, udp, tcp);

    #[cfg(feature = "mdns")]
    return NameServerPool::from_nameservers(
        &options,
        udp,
        tcp,
        _mdns.unwrap_or_else(|| mock_nameserver(vec![], options)),
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

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], Default::default());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], Default::default());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

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

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], Default::default());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], Default::default());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

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

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], Default::default());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], Default::default());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

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

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], Default::default());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], Default::default());
    let mdns_nameserver = mock_nameserver(vec![mdns_message.map(Into::into)], Default::default());

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        Some(mdns_nameserver),
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], mdns_record);
}

#[test]
fn test_trust_nx_responses_fails_servfail() {
    use trust_dns_proto::op::ResponseCode;

    let mut options = ResolverOpts::default();
    options.distrust_nx_responses = false;

    let query = Query::query(Name::from_str("www.example.").unwrap(), RecordType::A);

    let mut servfail_message = message(query.clone(), vec![], vec![], vec![]).unwrap();
    servfail_message.set_response_code(ResponseCode::ServFail);
    let servfail_message = Ok(servfail_message);

    let v4_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let success_msg = message(query.clone(), vec![v4_record.clone()], vec![], vec![]);

    let tcp_message = success_msg.clone();
    let udp_message = success_msg;

    let mut reactor = Runtime::new().unwrap();

    // fail the first udp request
    let udp_nameserver = mock_nameserver(
        vec![
            udp_message.clone().map(Into::into),
            servfail_message.clone().map(Into::into),
        ],
        options,
    );
    let tcp_nameserver =
        mock_nameserver(vec![Err(ProtoError::from("Forced Testing Error"))], options);

    let mut pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None, options);

    // lookup on UDP succeeds, any other would fail
    let request = message(query.clone(), vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert!(response.response_code() == ResponseCode::ServFail);

    // fail all udp succeed tcp
    let udp_nameserver = mock_nameserver(vec![servfail_message.map(Into::into)], options);
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], options);

    let mut pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None, options);

    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert!(response.response_code() == ResponseCode::ServFail);
}

#[test]
fn test_distrust_nx_responses() {
    use trust_dns_proto::op::ResponseCode;

    let mut options = ResolverOpts::default();
    options.distrust_nx_responses = true;

    let query = Query::query(Name::from_str("www.example.").unwrap(), RecordType::A);

    let mut servfail_message = message(query.clone(), vec![], vec![], vec![]).unwrap();
    servfail_message.set_response_code(ResponseCode::ServFail);
    let servfail_message = Ok(servfail_message);

    let v4_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let success_msg = message(query.clone(), vec![v4_record.clone()], vec![], vec![]);

    let tcp_message = success_msg.clone();
    //let udp_message = success_msg;

    let mut reactor = Runtime::new().unwrap();

    // fail the first udp request
    let udp_nameserver = mock_nameserver(vec![servfail_message.map(Into::into)], options);
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], options);

    let mut pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None, options);

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], v4_record);
}
