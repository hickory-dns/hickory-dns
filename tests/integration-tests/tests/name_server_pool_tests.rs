use std::net::*;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicIsize, Ordering},
    Arc,
};
use std::task::Poll;

use futures::executor::block_on;
use futures::{future, Future};

use hickory_client::op::{Query, ResponseCode};
use hickory_client::rr::{Name, RecordType};
use hickory_integration::mock_client::*;
use hickory_proto::error::{ProtoError, ProtoErrorKind};
use hickory_proto::xfer::{DnsHandle, DnsResponse, FirstAnswer};
use hickory_resolver::config::*;
use hickory_resolver::name_server::{NameServer, NameServerPool};

const DEFAULT_SERVER_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

type MockedNameServer<O> = NameServer<MockConnProvider<O>>;
type MockedNameServerPool<O> = NameServerPool<MockConnProvider<O>>;

#[cfg(test)]
fn mock_nameserver(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    options: ResolverOpts,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send_nx(messages, options, DefaultOnSend, DEFAULT_SERVER_ADDR, false)
}

#[cfg(test)]
fn mock_nameserver_with_addr(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    addr: IpAddr,
    options: ResolverOpts,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send_nx(messages, options, DefaultOnSend, addr, false)
}

#[cfg(test)]
fn mock_nameserver_trust_nx(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    options: ResolverOpts,
    trust_negative_responses: bool,
) -> MockedNameServer<DefaultOnSend> {
    mock_nameserver_on_send_nx(
        messages,
        options,
        DefaultOnSend,
        DEFAULT_SERVER_ADDR,
        trust_negative_responses,
    )
}

#[cfg(test)]
fn mock_nameserver_on_send<O: OnSend + Unpin>(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    options: ResolverOpts,
    on_send: O,
) -> MockedNameServer<O> {
    mock_nameserver_on_send_nx(messages, options, on_send, DEFAULT_SERVER_ADDR, false)
}

#[cfg(test)]
fn mock_nameserver_on_send_nx<O: OnSend + Unpin>(
    messages: Vec<Result<DnsResponse, ProtoError>>,
    options: ResolverOpts,
    on_send: O,
    addr: IpAddr,
    trust_negative_responses: bool,
) -> MockedNameServer<O> {
    let conn_provider = MockConnProvider {
        on_send: on_send.clone(),
    };
    let client = MockClientHandle::mock_on_send(messages, on_send);

    NameServer::from_conn(
        NameServerConfig {
            socket_addr: SocketAddr::new(addr, 0),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses,
            #[cfg(any(feature = "dns-over-rustls", feature = "dns-over-https-rustls"))]
            tls_config: None,
            bind_addr: None,
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
    mock_nameserver_pool_on_send::<DefaultOnSend>(udp, tcp, _mdns, options)
}

#[cfg(test)]
#[allow(clippy::redundant_clone)]
fn mock_nameserver_pool_on_send<O: OnSend + Unpin>(
    udp: Vec<MockedNameServer<O>>,
    tcp: Vec<MockedNameServer<O>>,
    _mdns: Option<MockedNameServer<O>>,
    options: ResolverOpts,
) -> MockedNameServerPool<O> {
    #[cfg(not(feature = "mdns"))]
    return NameServerPool::from_nameservers(options, udp, tcp);

    #[cfg(feature = "mdns")]
    return NameServerPool::from_nameservers(
        &options, udp,
        tcp,
        //_mdns.unwrap_or_else(move || mock_nameserver_on_send(vec![], options, on_send)),
    );
}

#[test]
fn test_datagram() {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));
    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);
    let tcp_message = message(query.clone(), vec![tcp_record], vec![], vec![]);
    let udp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        Default::default(),
    );
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}

#[test]
fn test_datagram_stream_upgrades_on_truncation() {
    // Lookup to UDP should return a truncated message, then we expect lookup on TCP.
    // This should occur even though `try_tcp_on_error` is set to false.

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let mut udp_message = message(query.clone(), vec![], vec![], vec![]);
    udp_message.set_truncated(true);

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let udp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        Default::default(),
    );
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
fn test_datagram_stream_upgrade_on_truncation_despite_udp() {
    // Lookup to UDP should return a truncated message, then we expect lookup on TCP.
    // This should occur even though `try_tcp_on_error` is set to false.

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));
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
        Default::default(),
    );
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    let response = block_on(future).unwrap();
    assert_eq!(response.answers(), &[tcp_record1, tcp_record2]);
}

#[test]
fn test_datagram_fails_to_stream() {
    // Lookup to UDP should fail, and then the query should be retried on TCP because
    // `try_tcp_on_error` is set to true.

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let udp_message: Result<DnsResponse, _> = Err(ProtoError::from("Forced Testing Error"));

    let tcp_message = message(query.clone(), vec![tcp_record.clone()], vec![], vec![]);

    let udp_nameserver = mock_nameserver(vec![udp_message], Default::default());
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        Default::default(),
    );

    let mut options = ResolverOpts::default();
    options.try_tcp_on_error = true;
    let pool = mock_nameserver_pool(vec![udp_nameserver], vec![tcp_nameserver], None, options);

    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();
    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], tcp_record);
}

#[test]
fn test_tcp_fallback_only_on_truncated() {
    // Lookup to UDP should fail with an error, and the resolver should not then try the query over
    // TCP, because the default behavior is only to retry if the response was truncated.

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let mut udp_message = message(query.clone(), vec![], vec![], vec![]);
    udp_message.set_response_code(ResponseCode::ServFail);
    let tcp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));
    let tcp_message = message(query.clone(), vec![tcp_record], vec![], vec![]);

    let udp_nameserver = mock_nameserver(
        vec![ProtoError::from_response(
            DnsResponse::from_message(udp_message).unwrap(),
            false,
        )],
        Default::default(),
    );
    let tcp_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(tcp_message).unwrap())],
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        None,
        Default::default(),
    );

    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();
    let error = block_on(future).expect_err("lookup request should fail with SERVFAIL");
    match error.kind() {
        ProtoErrorKind::NoRecordsFound { response_code, .. }
            if *response_code == ResponseCode::ServFail => {}
        kind => panic!(
            "got unexpected kind of resolve error; expected `NoRecordsFound` error with SERVFAIL,
            got {:#?}",
            kind,
        ),
    }
}

#[test]
#[cfg(feature = "mdns")]
fn test_local_mdns() {
    // lookup to UDP should fail
    // then lookup on TCP

    let query = Query::query(Name::from_str("www.example.local.").unwrap(), RecordType::A);

    let tcp_message: Result<DnsResponse, _> = Err(ResolveError::from("Forced Testing Error"));
    let udp_message: Result<DnsResponse, _> = Err(ResolveError::from("Forced Testing Error"));
    let mdns_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 2));

    let mdns_message = message(query.clone(), vec![mdns_record.clone()], vec![], vec![]);

    let udp_nameserver = mock_nameserver(vec![udp_message.map(Into::into)], Default::default());
    let tcp_nameserver = mock_nameserver(vec![tcp_message.map(Into::into)], Default::default());
    let mdns_nameserver = mock_nameserver(
        vec![Ok(DnsResponse::from_message(mdns_message).unwrap())],
        Default::default(),
    );

    let mut pool = mock_nameserver_pool(
        vec![udp_nameserver],
        vec![tcp_nameserver],
        Some(mdns_nameserver),
        Default::default(),
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request);

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], mdns_record);
}

#[test]
fn test_trust_nx_responses_fails() {
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
    let fail_nameserver = mock_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(nx_message).unwrap())],
        ResolverOpts::default(),
        true,
    );
    let succeed_nameserver = mock_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(success_msg).unwrap())],
        ResolverOpts::default(),
        true,
    );

    let pool = mock_nameserver_pool(
        vec![fail_nameserver, succeed_nameserver],
        vec![],
        None,
        ResolverOpts::default(),
    );

    // Lookup on UDP should fail, since we trust nx responses.
    // (If we retried the query with the second name server, we'd see a successful response.)
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();
    let response = block_on(future).expect_err("lookup request should fail with NXDOMAIN");
    match response.kind() {
        ProtoErrorKind::NoRecordsFound { response_code, .. }
            if *response_code == ResponseCode::NXDomain => {}
        kind => panic!(
            "got unexpected kind of resolve error; expected `NoRecordsFound` error with NXDOMAIN,
            got {:#?}",
            kind,
        ),
    }
}

#[test]
fn test_noerror_doesnt_leak() {
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

    let udp_nameserver = mock_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        Default::default(),
        true,
    );
    // Provide a fake A record; if this nameserver is queried the test should fail.
    let second_nameserver = mock_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(incorrect_success_msg).unwrap())],
        Default::default(),
        true,
    );

    let mut options = ResolverOpts::default();
    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    let pool = mock_nameserver_pool(
        vec![udp_nameserver, second_nameserver],
        vec![],
        None,
        options,
    );

    // lookup should only hit the first server
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    match block_on(future).unwrap_err().kind() {
        ProtoErrorKind::NoRecordsFound {
            soa,
            response_code,
            trusted,
            ..
        } => {
            assert_eq!(response_code, &ResponseCode::NoError);
            assert!(soa.is_some());
            assert!(trusted);
        }
        x => panic!("Expected NoRecordsFound, got {:?}", x),
    }
}

#[test]
#[allow(clippy::uninlined_format_args)]
fn test_distrust_nx_responses() {
    let query = Query::query(Name::from_str("www.example.").unwrap(), RecordType::A);

    const RETRYABLE_ERRORS: [ResponseCode; 9] = [
        ResponseCode::FormErr,
        ResponseCode::ServFail,
        ResponseCode::NotImp,
        ResponseCode::Refused,
        ResponseCode::YXDomain,
        ResponseCode::YXRRSet,
        ResponseCode::NXRRSet,
        ResponseCode::NotAuth,
        ResponseCode::NotZone,
    ];
    // Return an error response code, but have the client not trust that response.
    let error_nameserver = mock_nameserver_trust_nx(
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
    let fallback_nameserver = mock_nameserver_trust_nx(
        vec![Ok(DnsResponse::from_message(success_message).unwrap()); RETRYABLE_ERRORS.len()],
        ResolverOpts::default(),
        false,
    );

    let pool = mock_nameserver_pool(
        vec![error_nameserver, fallback_nameserver],
        vec![],
        None,
        ResolverOpts::default(),
    );
    for response_code in RETRYABLE_ERRORS.iter() {
        let request = message(query.clone(), vec![], vec![], vec![]);
        let fut = pool.send(request).first_answer();
        let response = block_on(fut).expect("query did not eventually succeed");
        assert_eq!(
            response.answers(),
            [v4_record.clone()],
            "did not see expected fallback behavior on response code `{}`",
            response_code
        );
    }
}

#[test]
fn test_user_provided_server_order() {
    use hickory_proto::rr::Record;

    let mut options = ResolverOpts::default();

    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let preferred_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));
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
    let preferred_nameserver = mock_nameserver_with_addr(
        to_dns_response(preferred_server_records.clone()),
        Ipv4Addr::new(128, 0, 0, 1).into(),
        Default::default(),
    );
    let secondary_nameserver = mock_nameserver_with_addr(
        to_dns_response(secondary_server_records.clone()),
        Ipv4Addr::new(129, 0, 0, 1).into(),
        Default::default(),
    );

    let pool = mock_nameserver_pool(
        vec![preferred_nameserver, secondary_nameserver],
        vec![],
        None,
        options,
    );

    // The returned records should consistently be from the preferred name
    // server until the configured records are exhausted. Subsequently, the
    // secondary server should be used.
    preferred_server_records
        .into_iter()
        .chain(secondary_server_records)
        .for_each(|expected_record| {
            let request = message(query.clone(), vec![], vec![], vec![]);
            let future = pool.send(request).first_answer();

            let response = block_on(future).unwrap();
            assert_eq!(response.answers()[0], expected_record);
        });
}

#[test]
fn test_return_error_from_highest_priority_nameserver() {
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
                ProtoError::from_response(DnsResponse::from_message(error_message).unwrap(), true)
                    .expect_err("error code should result in resolve error");
            mock_nameserver(vec![Err(response)], ResolverOpts::default())
        })
        .collect();
    let pool = mock_nameserver_pool(name_servers, vec![], None, ResolverOpts::default());

    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();
    let error = block_on(future).expect_err(
        "DNS query should result in a `ResolveError` since all name servers return error responses",
    );
    let expected_response_code = ERROR_RESPONSE_CODES.first().unwrap();
    eprintln!("error is: {error}");

    match error.kind() {
        ProtoErrorKind::NoRecordsFound { response_code, .. }
            if response_code == expected_response_code => {}
        kind => panic!(
            "got unexpected kind of resolve error; expected `NoRecordsFound` error with response \
            code `{:?}`, got {:#?}",
            expected_response_code, kind,
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
    ) -> Pin<Box<dyn Future<Output = Result<DnsResponse, E>> + Send>>
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
    future::poll_fn(move |_| {
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
    let mut options = ResolverOpts::default();

    // there are only 2 conns, so this matches that count
    options.num_concurrent_reqs = 2;

    // we want to make sure that both udp connections are called
    //   this will count down to 0 only if both are called.
    let on_send = OnSendBarrier::new(2);

    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let udp_record = v4_record(query.name().clone(), Ipv4Addr::new(127, 0, 0, 1));

    let udp_message = message(query.clone(), vec![udp_record.clone()], vec![], vec![]);

    let udp1_nameserver = mock_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send.clone(),
    );
    let udp2_nameserver = mock_nameserver_on_send(vec![], options.clone(), on_send);

    let pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
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

    let udp1_nameserver = mock_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send.clone(),
    );
    let udp2_nameserver = mock_nameserver_on_send(vec![], options.clone(), on_send);

    let pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
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

    let udp1_nameserver = mock_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send,
    );
    let udp2_nameserver = udp1_nameserver.clone();

    let pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
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

    let udp1_nameserver = mock_nameserver_on_send(
        vec![Ok(DnsResponse::from_message(udp_message).unwrap())],
        options.clone(),
        on_send,
    );
    let udp2_nameserver = udp1_nameserver.clone();

    let pool = mock_nameserver_pool_on_send(
        vec![udp2_nameserver, udp1_nameserver],
        vec![],
        None,
        options,
    );

    // lookup on UDP succeeds, any other would fail
    let request = message(query, vec![], vec![], vec![]);
    let future = pool.send(request).first_answer();

    // there's no actual network traffic happening, 1 sec should be plenty
    //   TODO: for some reason this timeout doesn't work, not clear why...
    // let future = Timeout::new(future, Duration::from_secs(1));

    let response = block_on(future).unwrap();
    assert_eq!(response.answers()[0], udp_record);
}
