use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::slice;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicIsize, Ordering},
};
use std::task::Poll;

use futures::{executor::block_on, future::BoxFuture};

use hickory_integration::mock_client::*;
use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::xfer::{DnsHandle, DnsResponse, FirstAnswer};
use hickory_proto::{NoRecords, ProtoError, ProtoErrorKind};
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::name_server::{NameServer, NameServerPool, TlsConfig};
use test_support::subscribe;

const DEFAULT_SERVER_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

type MockedNameServer<O> = NameServer<MockConnProvider<O>>;
type MockedNameServerPool<O> = NameServerPool<MockConnProvider<O>>;

#[cfg(test)]
fn mock_nameserver(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    protocol: ProtocolConfig,
    options: ResolverOpts,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send_nx(
        vec![(protocol, messages)],
        options,
        DefaultOnSend,
        DEFAULT_SERVER_ADDR,
        false,
    )
}

#[cfg(test)]
fn mock_udp_nameserver_with_addr(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    addr: IpAddr,
    options: ResolverOpts,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send_nx(
        vec![(ProtocolConfig::Udp, messages)],
        options,
        DefaultOnSend,
        addr,
        false,
    )
}

#[cfg(test)]
fn mock_udp_nameserver_trust_nx(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    options: ResolverOpts,
    trust_negative_responses: bool,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send_nx(
        vec![(ProtocolConfig::Udp, messages)],
        options,
        DefaultOnSend,
        DEFAULT_SERVER_ADDR,
        trust_negative_responses,
    )
}

#[cfg(test)]
fn mock_udp_nameserver_on_send<O: OnSend + Unpin>(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    options: ResolverOpts,
    on_send: O,
) -> MockedNameServer<O> {
    mock_nameserver_on_send_nx(
        vec![(ProtocolConfig::Udp, messages)],
        options,
        on_send,
        DEFAULT_SERVER_ADDR,
        false,
    )
}

#[cfg(test)]
fn mock_nameserver_on_send_nx<O: OnSend + Unpin>(
    protocols: Vec<(ProtocolConfig, Vec<Result<DnsResponse, ProtoError>>)>,
    options: ResolverOpts,
    on_send: O,
    ip: IpAddr,
    trust_negative_responses: bool,
) -> MockedNameServer<O> {
    let conn_provider = MockConnProvider {
        on_send: on_send.clone(),
    };

    let (mut configs, mut conns) = (Vec::new(), Vec::new());
    for (protocol, messages) in protocols {
        let proto = protocol.to_protocol();
        configs.push(ConnectionConfig::new(protocol));
        conns.push((
            proto,
            MockClientHandle::mock_on_send(messages, on_send.clone()),
        ));
    }

    let config = NameServerConfig::new(ip, trust_negative_responses, configs);
    NameServer::with_connections(
        conns,
        config,
        Arc::new(options),
        Arc::new(TlsConfig::new().unwrap()),
        conn_provider,
    )
}

#[cfg(test)]
fn mock_nameserver_pool(
    servers: Vec<MockedNameServer<DefaultOnSend>>,
    _mdns: Option<MockedNameServer<DefaultOnSend>>,
    options: ResolverOpts,
) -> MockedNameServerPool<DefaultOnSend> {
    mock_nameserver_pool_on_send::<DefaultOnSend>(servers, _mdns, options)
}

#[cfg(test)]
fn mock_nameserver_pool_on_send<O: OnSend + Unpin>(
    servers: Vec<MockedNameServer<O>>,
    _mdns: Option<MockedNameServer<O>>,
    options: ResolverOpts,
) -> MockedNameServerPool<O> {
    NameServerPool::from_nameservers(servers, Arc::new(options))
}

#[test]
fn test_datagram() {
    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);
    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);
    let udp_response = DnsResponse::from_message(udp_message).unwrap();

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let tcp_message = message(query.clone(), vec![tcp_record], vec![], vec![]);
    let tcp_response = DnsResponse::from_message(tcp_message).unwrap();

    let nameserver = mock_nameserver_on_send_nx(
        vec![
            (ProtocolConfig::Udp, vec![Ok(udp_response)]),
            (ProtocolConfig::Tcp, vec![Ok(tcp_response)]),
        ],
        ResolverOpts::default(),
        DefaultOnSend,
        DEFAULT_SERVER_ADDR,
        false,
    );

    let mut opts = ResolverOpts::default();
    opts.num_concurrent_reqs = 1;
    let pool = mock_nameserver_pool(vec![nameserver], None, opts);

    // lookup on UDP succeeds, any other would fail
    let request = build_request(query);
    let future = pool.send(request).first_answer();

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_datagram_stream_upgrades_on_truncation() {
    // Lookup to UDP should return a truncated message, then we expect lookup on TCP.
    // This should occur even though `try_tcp_on_error` is set to false.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let mut udp_message = message(query.clone(), vec![], vec![], vec![]);
    udp_message.set_truncated(true);

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let udp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        ProtocolConfig::Udp,
        Default::default(),
    );
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        ProtocolConfig::Tcp,
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![udp_nameserver, tcp_nameserver],
        None,
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let future = pool.send(build_request(query)).first_answer();

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
fn test_datagram_stream_upgrade_on_truncation_despite_udp() {
    // Lookup to UDP should return a truncated message, then we expect lookup on TCP.
    // This should occur even though `try_tcp_on_error` is set to false.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);
    let tcp_record1 = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let tcp_record2 = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 3));

    let mut udp_message = message(query.clone(), vec![udp_record], vec![], vec![]);
    udp_message.set_truncated(true);

    let tcp_message = message(
        query.clone(),
        vec![tcp_record1.clone(), tcp_record2.clone()],
        vec![],
        vec![],
    );

    let udp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        ProtocolConfig::Udp,
        Default::default(),
    );
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        ProtocolConfig::Tcp,
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![udp_nameserver, tcp_nameserver],
        None,
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let future = pool.send(build_request(query)).first_answer();

    let response = block_on(future).unwrap();
    assert_eq!(response.answers(), &[tcp_record1, tcp_record2]);
}

#[test]
fn test_datagram_fails_to_stream() {
    // Lookup to UDP should fail, and then the query should be retried on TCP because
    // `try_tcp_on_error` is set to true.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let io_error = std::io::Error::other("Some I/O Error");
    let udp_message: Result<DnsResponse, _> = Err(ProtoError::from(io_error));

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let udp_nameserver =
        mock_nameserver(vec![udp_message], ProtocolConfig::Udp, Default::default());
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        ProtocolConfig::Tcp,
        Default::default(),
    );

    let mut options = ResolverOpts::default();
    options.try_tcp_on_error = true;
    let pool = mock_nameserver_pool(vec![udp_nameserver, tcp_nameserver], None, options);

    let future = pool.send(build_request(query)).first_answer();
    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
fn test_tcp_fallback_only_on_truncated() {
    // Lookup to UDP should fail with an error, and the resolver should not then try the query over
    // TCP, because the default behavior is only to retry if the response was truncated.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let mut udp_message = message(query.clone(), vec![], vec![], vec![]);
    udp_message.set_response_code(ResponseCode::ServFail);
    let udp_response = DnsResponse::from_message(udp_message).unwrap();

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let tcp_message = message(query.clone(), vec![tcp_record], vec![], vec![]);
    let tcp_response = DnsResponse::from_message(tcp_message).unwrap();

    let nameserver = mock_nameserver_on_send_nx(
        vec![
            (ProtocolConfig::Udp, vec![Ok(udp_response)]),
            (ProtocolConfig::Tcp, vec![Ok(tcp_response)]),
        ],
        ResolverOpts::default(),
        DefaultOnSend,
        DEFAULT_SERVER_ADDR,
        false,
    );

    let pool = mock_nameserver_pool(vec![nameserver], None, Default::default());
    let future = pool.send(build_request(query)).first_answer();
    let error = block_on(future).expect_err("lookup request should fail with SERVFAIL");
    match error.kind() {
        ProtoErrorKind::ResponseCode(ResponseCode::ServFail) => {}
        kind => panic!(
            "got unexpected kind of resolve error; expected `ResponseCode` error with SERVFAIL,
            got {kind:#?}",
        ),
    }
}

#[test]
fn test_no_tcp_fallback_on_non_io_error() {
    // Lookup to UDP should fail with a non I/O error, and the resolver should not retry
    // the query over TCP when `try_tcp_on_error` is set to true.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let mut udp_message = message(query.clone(), vec![], vec![], vec![]);
    udp_message.set_response_code(ResponseCode::NXDomain);
    let udp_response = DnsResponse::from_message(udp_message).unwrap();

    let mut tcp_message = message(query.clone(), vec![], vec![], vec![]);
    tcp_message.set_response_code(ResponseCode::NotImp); // assuming a NotImp to distinguish with UDP response
    let tcp_response = DnsResponse::from_message(tcp_message).unwrap();

    let mut options = ResolverOpts::default();
    options.num_concurrent_reqs = 1;
    options.try_tcp_on_error = true;
    let nameserver = mock_nameserver_on_send_nx(
        vec![
            (ProtocolConfig::Udp, vec![Ok(udp_response)]),
            (ProtocolConfig::Tcp, vec![Ok(tcp_response)]),
        ],
        options.clone(),
        DefaultOnSend,
        DEFAULT_SERVER_ADDR,
        false,
    );

    let pool = mock_nameserver_pool(vec![nameserver], None, options);
    let future = pool.send(build_request(query)).first_answer();
    let error = block_on(future).expect_err("DNS query should result in a `NXDomain`");
    match error.kind() {
        ProtoErrorKind::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NXDomain,
            ..
        }) => {}
        kind => panic!(
            "expected `NoRecordsFound` with `response_code: NXDomain`,
            got {kind:#?}",
        ),
    }
}

#[test]
fn test_tcp_fallback_on_io_error() {
    // Lookup to UDP should fail with an I/O error, and the resolver should then try
    // the query over TCP when `try_tcp_on_error` is set to true.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let io_error = std::io::Error::other("Some I/O Error");
    let udp_message: Result<DnsResponse, _> = Err(ProtoError::from(io_error));

    let mut tcp_message = message(query.clone(), vec![], vec![], vec![]);
    tcp_message.set_response_code(ResponseCode::NotImp);

    let udp_nameserver =
        mock_nameserver(vec![udp_message], ProtocolConfig::Udp, Default::default());

    let tcp_nameserver = mock_nameserver(
        vec![ProtoError::from_response(
            DnsResponse::from_message(tcp_message).unwrap(),
        )],
        ProtocolConfig::Tcp,
        Default::default(),
    );

    let mut options = ResolverOpts::default();
    options.try_tcp_on_error = true;
    let pool = mock_nameserver_pool(vec![udp_nameserver, tcp_nameserver], None, options);

    let future = pool.send(build_request(query)).first_answer();
    let error = block_on(future).expect_err("DNS query should result in a `NotImp`");
    match error.kind() {
        ProtoErrorKind::ResponseCode(ResponseCode::NotImp) => {}
        kind => panic!(
            "expected `ResponseCode` with `response_code: NotImp`,
            got {kind:#?}",
        ),
    }
}

#[test]
fn test_tcp_fallback_on_no_connections() {
    // Lookup to UDP should fail with a NoConnections error, and the resolver should then try
    // the query over TCP whether `try_tcp_on_error` is set to true or not.

    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_message: Result<DnsResponse, _> = Err(ProtoError::from(ProtoErrorKind::NoConnections));

    let mut tcp_message = message(query.clone(), vec![], vec![], vec![]);
    tcp_message.set_response_code(ResponseCode::NotImp);

    let udp_nameserver =
        mock_nameserver(vec![udp_message], ProtocolConfig::Udp, Default::default());

    let tcp_nameserver = mock_nameserver(
        vec![ProtoError::from_response(
            DnsResponse::from_message(tcp_message).unwrap(),
        )],
        ProtocolConfig::Tcp,
        Default::default(),
    );

    let mut options = ResolverOpts::default();
    options.try_tcp_on_error = true;
    let pool = mock_nameserver_pool(vec![udp_nameserver, tcp_nameserver], None, options);

    let future = pool.send(build_request(query)).first_answer();
    let error = block_on(future).expect_err("DNS query should result in a `NotImp`");
    match error.kind() {
        ProtoErrorKind::ResponseCode(ResponseCode::NotImp) => {}
        kind => panic!(
            "expected `ResponseCode` with `response_code: NotImp`,
            got {kind:#?}",
        ),
    }
}

#[test]
fn test_trust_nx_responses_fails() {
    subscribe();

    let query = Query::query(Name::from_str("www.example.").unwrap(), RecordType::A);

    // NXDOMAIN responses are only trusted if there's a SOA record, so make sure we return one.
    let soa_record = soa_record(
        query.name().clone(),
        Name::from_str("example.com.").unwrap(),
    );
    let mut nx_message = message(query.clone(), vec![], vec![soa_record], vec![]);
    nx_message.set_response_code(ResponseCode::NXDomain);

    let success_msg = message(
        query.clone(),
        vec![v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2))],
        vec![],
        vec![],
    );

    // Fail the first UDP request.
    let fail_nameserver = mock_udp_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(nx_message).unwrap())],
        ResolverOpts::default(),
        true,
    );
    let succeed_nameserver = mock_udp_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(success_msg).unwrap())],
        ResolverOpts::default(),
        true,
    );

    let mut opts = ResolverOpts::default();
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    let pool = mock_nameserver_pool(vec![fail_nameserver, succeed_nameserver], None, opts);

    // Lookup on UDP should fail, since we trust nx responses.
    // (If we retried the query with the second name server, we'd see a successful response.)
    let future = pool.send(build_request(query)).first_answer();
    let response = block_on(future).expect_err("lookup request should fail with NXDOMAIN");
    match response.kind() {
        ProtoErrorKind::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NXDomain,
            ..
        }) => {}
        kind => panic!(
            "got unexpected kind of resolve error; expected `NoRecordsFound` error with NXDOMAIN,
            got {kind:#?}",
        ),
    }
}

#[test]
fn test_noerror_doesnt_leak() {
    subscribe();

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let soa_record = soa_record(
        query.name().clone(),
        Name::from_str("example.com.").unwrap(),
    );
    let udp_message = message(query.clone(), vec![], vec![soa_record], vec![]);

    let incorrect_success_msg = message(
        query.clone(),
        vec![v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2))],
        vec![],
        vec![],
    );

    let udp_nameserver = mock_udp_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        Default::default(),
        true,
    );
    // Provide a fake A record; if this nameserver is queried the test should fail.
    let second_nameserver = mock_udp_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(incorrect_success_msg).unwrap())],
        Default::default(),
        true,
    );

    let mut options = ResolverOpts::default();
    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    let pool = mock_nameserver_pool(vec![udp_nameserver, second_nameserver], None, options);

    // lookup should only hit the first server
    let future = pool.send(build_request(query)).first_answer();
    match block_on(future).unwrap_err().kind() {
        ProtoErrorKind::NoRecordsFound(NoRecords {
            soa, response_code, ..
        }) => {
            assert_eq!(response_code, &ResponseCode::NoError);
            assert!(soa.is_some());
        }
        x => panic!("Expected NoRecordsFound, got {x:?}"),
    }
}

#[test]
#[allow(clippy::uninlined_format_args)]
fn test_distrust_nx_responses() {
    subscribe();

    let query = Query::query(Name::from_str("www.example.").unwrap(), RecordType::A);

    const RETRYABLE_ERRORS: &[ResponseCode] = &[ResponseCode::NXDomain];
    // Return an error response code, but have the client not trust that response.
    let error_nameserver = mock_udp_nameserver_trust_nx(
        RETRYABLE_ERRORS
            .iter()
            .map(|response_code| {
                let mut error_message = message(query.clone(), vec![], vec![], vec![]);
                error_message.set_response_code(*response_code);
                Ok(DnsResponse::from_message(error_message).unwrap())
            })
            .collect(),
        ResolverOpts::default(),
        false,
    );

    // Return a successful response on the fallback request.
    let v4_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let success_message = message(query.clone(), vec![v4_record.clone()], vec![], vec![]);
    let fallback_nameserver = mock_udp_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(success_message).unwrap()); RETRYABLE_ERRORS.len()],
        ResolverOpts::default(),
        false,
    );

    let mut opts = ResolverOpts::default();
    opts.num_concurrent_reqs = 1;
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    let pool = mock_nameserver_pool(vec![error_nameserver, fallback_nameserver], None, opts);
    for response_code in RETRYABLE_ERRORS.iter() {
        let fut = pool.send(build_request(query.clone())).first_answer();
        let response = block_on(fut).expect("query did not eventually succeed");
        assert_eq!(
            response.answers(),
            slice::from_ref(&v4_record),
            "did not see expected fallback behavior on response code `{}`",
            response_code
        );
    }
}

#[test]
fn test_user_provided_server_order() {
    use hickory_proto::rr::Record;

    subscribe();

    let mut options = ResolverOpts::default();

    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let preferred_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);
    let secondary_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let preferred_server_records = vec![preferred_record; 10];
    let secondary_server_records = vec![secondary_record; 10];

    let to_dns_response = |records: Vec<Record>| -> Vec<Result<DnsResponse, ProtoError>> {
        records
            .iter()
            .map(|record| {
                Ok(DnsResponse::from_message(message(
                    query.clone(),
                    vec![record.clone()],
                    vec![],
                    vec![],
                ))
                .unwrap())
            })
            .collect()
    };

    // Specify different IP addresses for each name server to ensure that they
    // are considered separately.
    let mut preferred_server_responses = to_dns_response(preferred_server_records.clone());
    preferred_server_responses.insert(0, Err(ProtoError::from(io::Error::other("fail"))));
    let preferred_nameserver = mock_udp_nameserver_with_addr(
        preferred_server_responses,
        Ipv4Addr::new(128, 0, 0, 1).into(),
        Default::default(),
    );
    let secondary_nameserver = mock_udp_nameserver_with_addr(
        to_dns_response(secondary_server_records.clone()),
        Ipv4Addr::new(129, 0, 0, 1).into(),
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![preferred_nameserver, secondary_nameserver],
        None,
        options,
    );

    // The returned records should consistently be from the preferred name
    // server until the configured records are exhausted. Subsequently, the
    // secondary server should be used.
    preferred_server_records
        .into_iter()
        .chain(secondary_server_records.into_iter().take(1))
        .for_each(|expected_record| {
            let future = pool.send(build_request(query.clone())).first_answer();
            let response = block_on(future).unwrap();
            assert_eq!(response.answers()[0], expected_record);
        });
}

#[test]
fn test_return_error_from_highest_priority_nameserver() {
    subscribe();

    let query = Query::query(Name::from_str("www.example.").unwrap(), RecordType::A);

    const ERROR_RESPONSE_CODES: [ResponseCode; 4] = [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::FormErr,
        ResponseCode::NotImp,
    ];
    let name_servers = ERROR_RESPONSE_CODES
        .iter()
        .map(|response_code| {
            let mut error_message = message(query.clone(), vec![], vec![], vec![]);
            error_message.set_response_code(*response_code);
            let response =
                ProtoError::from_response(DnsResponse::from_message(error_message).unwrap())
                    .expect_err("error code should result in resolve error");
            mock_nameserver(
                vec![Err(response)],
                ProtocolConfig::Udp,
                ResolverOpts::default(),
            )
        })
        .collect();

    let mut opts = ResolverOpts::default();
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    let pool = mock_nameserver_pool(name_servers, None, opts);

    let future = pool.send(build_request(query)).first_answer();
    let error = block_on(future).expect_err(
        "DNS query should result in a `ResolveError` since all name servers return error responses",
    );
    let expected_response_code = ERROR_RESPONSE_CODES.first().unwrap();
    eprintln!("error is: {error}");

    match error.kind() {
        ProtoErrorKind::ResponseCode(response_code) if response_code == expected_response_code => {}
        kind => panic!(
            "got unexpected kind of resolve error; expected error with response \
            code `{expected_response_code:?}`, got {kind:#?}",
        ),
    }
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
    fn on_send<E>(
        &self,
        response: Result<DnsResponse, E>,
    ) -> BoxFuture<'static, Result<DnsResponse, E>>
    where
        E: From<ProtoError> + Send + 'static,
    {
        self.barrier.fetch_sub(1, Ordering::Relaxed);

        let barrier = self.barrier.clone();
        let loop_future = wait_for(barrier, response);

        Box::pin(loop_future)
    }
}

async fn wait_for<E>(
    barrier: Arc<AtomicIsize>,
    response: Result<DnsResponse, E>,
) -> Result<DnsResponse, E>
where
    E: From<ProtoError> + Send + 'static,
{
    poll_fn(move |_| {
        if barrier.load(Ordering::Relaxed) > 0 {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;

    println!("done waiting");
    response
}

#[test]
fn test_concurrent_requests_2_conns() {
    subscribe();

    let mut options = ResolverOpts::default();
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;

    // there are only 2 conns, so this matches that count
    options.num_concurrent_reqs = 2;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(2);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let udp1_nameserver = mock_udp_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send.clone(),
    );
    let udp2_nameserver = mock_udp_nameserver_on_send(vec![], options.clone(), on_send);

    let pool = mock_nameserver_pool_on_send(vec![udp2_nameserver, udp1_nameserver], None, options);

    // lookup on UDP succeeds, any other would fail
    let future = pool.send(build_request(query)).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_concurrent_requests_more_than_conns() {
    subscribe();

    let mut options = ResolverOpts::default();
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;

    // there are only two conns, but this requests 3 concurrent requests, only 2 called
    options.num_concurrent_reqs = 3;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(2);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let udp1_nameserver = mock_udp_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send.clone(),
    );
    let udp2_nameserver = mock_udp_nameserver_on_send(vec![], options.clone(), on_send);

    let pool = mock_nameserver_pool_on_send(vec![udp2_nameserver, udp1_nameserver], None, options);

    // lookup on UDP succeeds, any other would fail
    let future = pool.send(build_request(query)).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_concurrent_requests_1_conn() {
    subscribe();

    let mut options = ResolverOpts::default();

    // there are two connections, but no concurrency requested
    options.num_concurrent_reqs = 1;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(1);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let udp1_nameserver = mock_udp_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send,
    );
    let udp2_nameserver = udp1_nameserver.clone();

    let pool = mock_nameserver_pool_on_send(vec![udp2_nameserver, udp1_nameserver], None, options);

    // lookup on UDP succeeds, any other would fail
    let future = pool.send(build_request(query)).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_concurrent_requests_0_conn() {
    subscribe();

    let mut options = ResolverOpts::default();

    // there are two connections, but no concurrency requested, 0==1
    options.num_concurrent_reqs = 0;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(1);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::LOCALHOST);

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let udp1_nameserver = mock_udp_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send,
    );
    let udp2_nameserver = udp1_nameserver.clone();

    let pool = mock_nameserver_pool_on_send(vec![udp2_nameserver, udp1_nameserver], None, options);

    // lookup on UDP succeeds, any other would fail
    let future = pool.send(build_request(query)).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}
