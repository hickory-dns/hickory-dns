extern crate futures;
extern crate tokio;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_resolver;

use std::net::*;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicIsize, Ordering},
    Arc,
};

use futures::future::{self, Future, Loop};
use tokio::runtime::current_thread::Runtime;

use trust_dns::op::Query;
use trust_dns::rr::{Name, RecordType};
use trust_dns_integration::mock_client::*;
use trust_dns_proto::error::{ProtoError, ProtoResult};
use trust_dns_proto::xfer::{DnsHandle, DnsResponse};
use trust_dns_resolver::config::*;
use trust_dns_resolver::name_server::{ConnectionProvider, NameServer, NameServerPool};

#[derive(Clone)]
struct MockConnProvider<O: OnSend> {
    on_send: O,
}

impl Default for MockConnProvider<DefaultOnSend> {
    fn default() -> Self {
        Self {
            on_send: DefaultOnSend,
        }
    }
}

impl<O: OnSend> ConnectionProvider for MockConnProvider<O> {
    type ConnHandle = MockClientHandle<O>;

    fn new_connection(&self, _: &NameServerConfig, _: &ResolverOpts) -> Self::ConnHandle {
        MockClientHandle::mock_on_send(vec![], self.on_send.clone())
    }
}

type MockedNameServer<O> = NameServer<MockClientHandle<O>, MockConnProvider<O>>;
type MockedNameServerPool<O> = NameServerPool<MockClientHandle<O>, MockConnProvider<O>>;

#[cfg(test)]
fn mock_nameserver(
    messages: Vec<ProtoResult<DnsResponse>>,
    options: ResolverOpts,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send(messages, options, DefaultOnSend)
}

#[cfg(test)]
fn mock_nameserver_on_send<O: OnSend>(
    messages: Vec<ProtoResult<DnsResponse>>,
    options: ResolverOpts,
    on_send: O,
) -> MockedNameServer<O> {
    let conn_provider = MockConnProvider {
        on_send: on_send.clone(),
    };
    let client = MockClientHandle::mock_on_send(messages, on_send);

    NameServer::from_conn(
        NameServerConfig {
            socket_addr: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 0),
            protocol: Protocol::Udp,
            tls_dns_name: None,
        },
        options,
        client,
        conn_provider,
    )
}

#[cfg(test)]
fn mock_nameserver_pool(
    udp: Vec<MockedNameServer<DefaultOnSend>>,
    tcp: Vec<MockedNameServer<DefaultOnSend>>,
    _mdns: Option<MockedNameServer<DefaultOnSend>>,
    options: ResolverOpts,
) -> MockedNameServerPool<DefaultOnSend> {
    mock_nameserver_pool_on_send::<DefaultOnSend>(udp, tcp, _mdns, options, DefaultOnSend)
}

#[cfg(test)]
fn mock_nameserver_pool_on_send<O: OnSend>(
    udp: Vec<MockedNameServer<O>>,
    tcp: Vec<MockedNameServer<O>>,
    _mdns: Option<MockedNameServer<O>>,
    options: ResolverOpts,
    on_send: O,
) -> MockedNameServerPool<O> {
    let conn_provider = MockConnProvider {
        on_send: on_send.clone(),
    };

    #[cfg(not(feature = "mdns"))]
    return NameServerPool::from_nameservers(&options, udp, tcp, conn_provider);

    #[cfg(feature = "mdns")]
    return NameServerPool::from_nameservers(
        &options,
        udp,
        tcp,
        _mdns.unwrap_or_else(|| mock_nameserver_on_send(vec![], options, on_send)),
        conn_provider,
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

// === Concurrent requests ===

#[derive(Clone)]
struct OnSendBarrier {
    barrier: Arc<AtomicIsize>,
}

impl OnSendBarrier {
    fn new(count: isize) -> Self {
        Self {
            barrier: Arc::new(AtomicIsize::new(count)),
        }
    }
}

impl OnSend for OnSendBarrier {
    fn on_send(
        &mut self,
        response: Result<DnsResponse, ProtoError>,
    ) -> Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send> {
        self.barrier.fetch_sub(1, Ordering::Relaxed);

        // loop until the barrier is 0
        let loop_future = future::loop_fn(
            (self.barrier.clone(), response),
            move |(barrier, response)| {
                let remaining = barrier.load(Ordering::Relaxed);

                match remaining {
                    0 => response.map(Loop::Break),
                    i if i > 0 => Ok(Loop::Continue((barrier, response))),
                    i if i < 0 => panic!("more concurrency than expected: {}", i),
                    _ => panic!("all other cases handled"),
                }
            },
        );

        Box::new(loop_future)
    }
}

#[test]
fn test_concurrent_requests() {
    let mut options = ResolverOpts::default();
    // there are only 2 conns, so this matches that count
    options.num_concurrent_reqs = 2;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(2);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp1_nameserver =
        mock_nameserver_on_send(vec![udp_message.map(Into::into)], options, on_send.clone());
    let udp2_nameserver = udp1_nameserver.clone();

    let mut pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
        on_send,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_concurrent_requests_more_than_conns() {
    let mut options = ResolverOpts::default();
    // there are only two conns, but this requests 3 concurrent requests, only 2 called
    options.num_concurrent_reqs = 3;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(2);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp1_nameserver =
        mock_nameserver_on_send(vec![udp_message.map(Into::into)], options, on_send.clone());
    let udp2_nameserver = udp1_nameserver.clone();

    let mut pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
        on_send,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_concurrent_requests_1_conn() {
    let mut options = ResolverOpts::default();
    // there are two connections, but no concurrency requested
    options.num_concurrent_reqs = 1;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(1);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp1_nameserver =
        mock_nameserver_on_send(vec![udp_message.map(Into::into)], options, on_send.clone());
    let udp2_nameserver = udp1_nameserver.clone();

    let mut pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
        on_send,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_concurrent_requests_0_conn() {
    let mut options = ResolverOpts::default();
    // there are two connections, but no concurrency requested, 0==1
    options.num_concurrent_reqs = 0;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(1);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let mut reactor = Runtime::new().unwrap();

    let udp1_nameserver =
        mock_nameserver_on_send(vec![udp_message.map(Into::into)], options, on_send.clone());
    let udp2_nameserver = udp1_nameserver.clone();

    let mut pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
        on_send,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]).unwrap();
    let future = pool.send(request);

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = reactor.block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}
