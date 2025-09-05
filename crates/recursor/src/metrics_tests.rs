use std::{
    cmp,
    collections::{HashMap, VecDeque},
    future::{Future, ready},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bytes::Buf;
use futures_util::{AsyncRead, AsyncWrite};
use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, NS},
    },
    runtime::{RuntimeProvider, TokioHandle, TokioTime},
    serialize::binary::BinDecodable,
    tcp::DnsTcpStream,
    udp::DnsUdpSocket,
};
use hickory_resolver::Name;
use metrics::{Key, Unit, with_local_recorder};
use metrics_util::{
    CompositeKey, MetricKind,
    debugging::{DebugValue, DebuggingRecorder},
};
use test_support::subscribe;
use tokio::runtime::Builder;
use tracing::{error, info};

use crate::Recursor;

const ROOT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
const TLD_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1);
const LEAF_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 1);
const A_RR_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

#[test]
fn test_recursor_metrics() {
    subscribe();
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let query_name = Name::parse("hickory-dns.testing.", None).unwrap();

    with_local_recorder(&recorder, || {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let handler = MockNetworkHandler::new();
        let provider = MockProvider::new(handler);
        runtime.block_on(async {
            let recursor = Recursor::builder_with_provider(provider)
                .clear_deny_servers() // We use addresses in the default deny filter.
                .build(&[ROOT_IP.into()])
                .unwrap();
            for _ in 0..3 {
                let response = recursor
                    .resolve(
                        Query::query(query_name.clone(), RecordType::A),
                        Instant::now(),
                        false,
                    )
                    .await
                    .unwrap();
                assert_eq!(response.response_code(), ResponseCode::NoError);
            }
        });
    });

    #[allow(clippy::mutable_key_type)] // False positive, see the documentation for metrics::Key.
    let map = snapshotter.snapshot().into_hashmap();

    let (unit_opt, description_opt, value) = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_name("hickory_recursor_outgoing_queries_total"),
        ))
        .unwrap();
    assert_eq!(unit_opt, &Some(Unit::Count));
    assert!(description_opt.is_some());
    assert_eq!(value, &DebugValue::Counter(3));

    let (unit_opt, description_opt, value) = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_name("hickory_recursor_cache_hit_total"),
        ))
        .unwrap();
    assert_eq!(unit_opt, &Some(Unit::Count));
    assert!(description_opt.is_some());
    assert_eq!(value, &DebugValue::Counter(2));

    let (unit_opt, description_opt, value) = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            Key::from_name("hickory_recursor_cache_miss_total"),
        ))
        .unwrap();
    assert_eq!(unit_opt, &Some(Unit::Count));
    assert!(description_opt.is_some());
    assert_eq!(value, &DebugValue::Counter(1));
}

/// Request handling functionality that can be plugged into [`MockProvider`].
trait MockHandler {
    /// Takes in a request message and produces a response message.
    fn handle(&self, destination: IpAddr, request: Message) -> Message;
}

/// Handler that stands in for multiple authoritative name servers, with specific canned responses.
struct MockNetworkHandler {
    responses: HashMap<IpAddr, HashMap<Query, Message>>,
}

impl MockNetworkHandler {
    fn new() -> Self {
        const TTL: u32 = 3600;

        let tld_name = Name::parse("testing.", None).unwrap();
        let leaf_name = Name::parse("hickory-dns.testing.", None).unwrap();

        let tld_server_name = Name::parse("testing.nameservers.net.", None).unwrap();
        let leaf_server_name = Name::parse("leaf.nameservers.net.", None).unwrap();

        let mut root_responses = HashMap::new();

        // Request for `testing. IN NS` sent to the root zone name server. Referral response.
        let mut root_testing_ns_response = Message::response(0, OpCode::Query);
        root_testing_ns_response.add_query(Query::query(tld_name.clone(), RecordType::NS));
        root_testing_ns_response.add_authority(Record::from_rdata(
            tld_name.clone(),
            TTL,
            RData::NS(NS(tld_server_name.clone())),
        ));
        root_testing_ns_response.add_additional(Record::from_rdata(
            tld_server_name.clone(),
            TTL,
            RData::A(A(TLD_IP)),
        ));
        root_responses.insert(
            root_testing_ns_response.queries()[0].clone(),
            root_testing_ns_response,
        );

        let mut tld_responses = HashMap::new();

        // Request for `hickory-dns.testing. IN NS` sent to the TLD zone name server. Referral response.
        let mut tld_leaf_ns_response = Message::response(0, OpCode::Query);
        tld_leaf_ns_response.add_query(Query::query(leaf_name.clone(), RecordType::NS));
        tld_leaf_ns_response.add_answer(Record::from_rdata(
            leaf_name.clone(),
            TTL,
            RData::NS(NS(leaf_server_name.clone())),
        ));
        tld_leaf_ns_response.add_additional(Record::from_rdata(
            leaf_server_name.clone(),
            TTL,
            RData::A(A(LEAF_IP)),
        ));
        tld_responses.insert(
            tld_leaf_ns_response.queries()[0].clone(),
            tld_leaf_ns_response,
        );

        let mut leaf_responses = HashMap::new();

        // Request for `hickory-dns.testing.` IN A sent to the leaf zone name server. Authoritative response.
        let mut leaf_leaf_a_response = Message::response(0, OpCode::Query);
        leaf_leaf_a_response.add_query(Query::query(leaf_name.clone(), RecordType::A));
        leaf_leaf_a_response.set_authoritative(true);
        leaf_leaf_a_response.add_answer(Record::from_rdata(
            leaf_name.clone(),
            TTL,
            RData::A(A(A_RR_IP)),
        ));
        leaf_responses.insert(
            leaf_leaf_a_response.queries()[0].clone(),
            leaf_leaf_a_response,
        );

        Self {
            responses: HashMap::from([
                (ROOT_IP.into(), root_responses),
                (TLD_IP.into(), tld_responses),
                (LEAF_IP.into(), leaf_responses),
            ]),
        }
    }
}

impl MockHandler for MockNetworkHandler {
    fn handle(&self, destination: IpAddr, request: Message) -> Message {
        let Some(server_responses) = self.responses.get(&destination) else {
            error!(%destination, "unexpected destination IP address");
            return Message::error_msg(request.id(), request.op_code(), ResponseCode::ServFail);
        };
        let query = &request.queries()[0];
        info!(%destination, %query, "handling request");
        let Some(response) = server_responses.get(query) else {
            error!(%query, "unexpected query");
            return Message::error_msg(request.id(), request.op_code(), ResponseCode::ServFail);
        };
        let mut response = response.clone();
        response.set_id(request.id());
        response
    }
}

#[derive(Clone)]
struct MockProvider {
    handler: Arc<dyn MockHandler + Send + Sync>,
    tokio_handle: TokioHandle,
}

impl MockProvider {
    fn new(handler: impl MockHandler + Send + Sync + 'static) -> Self {
        Self {
            handler: Arc::new(handler),
            tokio_handle: TokioHandle::default(),
        }
    }
}

impl RuntimeProvider for MockProvider {
    type Handle = TokioHandle;

    type Timer = TokioTime;

    type Udp = MockUdpSocket;

    type Tcp = MockTcpStream;

    fn create_handle(&self) -> Self::Handle {
        self.tokio_handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        _timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tcp>> + Send>> {
        Box::pin(ready(Ok(MockTcpStream::new(
            self.handler.clone(),
            server_addr.ip(),
        ))))
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Udp>> + Send>> {
        Box::pin(ready(Ok(MockUdpSocket::new(self.handler.clone()))))
    }
}

struct MockUdpSocket {
    inner: Mutex<MockUdpSocketInner>,
    handler: Arc<dyn MockHandler + Send + Sync + 'static>,
}

struct MockUdpSocketInner {
    /// Response messages ready to be returned to the client.
    incoming_datagrams: VecDeque<(Message, SocketAddr)>,
    /// Waker from the last call to [`Self::poll_recv_from()`], if it returned `Pending`.
    waker: Option<Waker>,
}

impl MockUdpSocket {
    fn new(handler: Arc<dyn MockHandler + Send + Sync + 'static>) -> Self {
        Self {
            inner: Mutex::new(MockUdpSocketInner {
                incoming_datagrams: VecDeque::new(),
                waker: None,
            }),
            handler,
        }
    }
}

impl DnsUdpSocket for MockUdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut guard = self.inner.lock().unwrap();
        let Some((message, socket_addr)) = guard.incoming_datagrams.pop_front() else {
            guard.waker = Some(cx.waker().clone());
            return Poll::Pending;
        };

        let encoded = match message.to_vec() {
            Ok(vec) => vec,
            Err(error) => {
                error!(%error, "encoding response message failed");
                return Poll::Ready(Err(io::Error::other(error)));
            }
        };
        buf[..encoded.len()].copy_from_slice(&encoded);
        Poll::Ready(Ok((encoded.len(), socket_addr)))
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let request = match Message::from_bytes(buf) {
            Ok(message) => message,
            Err(error) => {
                error!(%error, "decoding request message failed");
                return Poll::Ready(Err(io::Error::other(error)));
            }
        };
        let response = self.handler.handle(target.ip(), request);

        let mut guard = self.inner.lock().unwrap();
        guard.incoming_datagrams.push_back((response, target));

        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }

        Poll::Ready(Ok(buf.len()))
    }
}

struct MockTcpStream {
    inner: Mutex<MockTcpStreamInner>,
    destination: IpAddr,
    handler: Arc<dyn MockHandler + Send + Sync + 'static>,
}

struct MockTcpStreamInner {
    /// Buffered stream data, from the client to the mocked server.
    ///
    /// This is produced via [`AsyncRead::poll_write()`], and consumed whenever a full message has
    /// been buffered.
    outgoing_buffer: VecDeque<u8>,
    /// Buffered stream data, from the mocked server back to the client.
    ///
    /// This is consumed via [`AsyncRead::poll_read()`].
    incoming_buffer: VecDeque<u8>,
    /// Waker from the last call to [`AsyncRead::poll_read()`], if it returned `Pending`.
    waker: Option<Waker>,
}

impl MockTcpStream {
    fn new(handler: Arc<dyn MockHandler + Send + Sync + 'static>, destination: IpAddr) -> Self {
        Self {
            inner: Mutex::new(MockTcpStreamInner {
                outgoing_buffer: VecDeque::new(),
                incoming_buffer: VecDeque::new(),
                waker: None,
            }),
            destination,
            handler,
        }
    }
}

impl DnsTcpStream for MockTcpStream {
    type Time = TokioTime;
}

impl AsyncRead for MockTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = self.inner.lock().unwrap();
        let len = guard.incoming_buffer.len();
        if len == 0 {
            guard.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let clamped_len = cmp::min(len, buf.len());
        guard.incoming_buffer.copy_to_slice(&mut buf[..clamped_len]);
        Poll::Ready(Ok(clamped_len))
    }
}

impl AsyncWrite for MockTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = self.inner.lock().unwrap();
        guard.outgoing_buffer.extend(buf);

        let mut any_writes = false;
        while guard.outgoing_buffer.len() >= 2 {
            let request_length_prefix = u16::from_be_bytes([
                *guard.outgoing_buffer.front().unwrap(),
                *guard.outgoing_buffer.get(1).unwrap(),
            ]);
            if guard.outgoing_buffer.len() < 2 + request_length_prefix as usize {
                break;
            }

            guard.outgoing_buffer.advance(2);
            let mut message_buf = vec![0u8; request_length_prefix as usize];
            guard.outgoing_buffer.copy_to_slice(&mut message_buf);

            let request = match Message::from_bytes(&message_buf) {
                Ok(message) => message,
                Err(error) => {
                    error!(%error, "decoding request message failed");
                    return Poll::Ready(Err(io::Error::other(error)));
                }
            };
            let response = self.handler.handle(self.destination, request);

            let encoded = match response.to_vec() {
                Ok(vec) => vec,
                Err(error) => {
                    error!(%error, "encoding response message failed");
                    return Poll::Ready(Err(io::Error::other(error)));
                }
            };

            guard
                .incoming_buffer
                .extend(u16::to_be_bytes(u16::try_from(encoded.len()).unwrap()));
            guard.incoming_buffer.extend(&encoded);

            any_writes = true;
        }

        if any_writes {
            if let Some(waker) = guard.waker.take() {
                waker.wake();
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
