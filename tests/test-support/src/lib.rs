use std::{
    cmp,
    collections::{HashMap, VecDeque},
    future::{Future, ready},
    io,
    io::Write,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, Once},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Buf;
use futures_util::{AsyncRead, AsyncWrite};
use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, NS, SOA},
    },
    runtime::{RuntimeProvider, TokioHandle, TokioTime},
    serialize::binary::BinDecodable,
    tcp::DnsTcpStream,
    udp::DnsUdpSocket,
};
use hickory_resolver::config::ProtocolConfig;
use tracing::{error, info};

/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
pub fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

/// This is a writer that can be used with a thread-local tracing subscriber to inspect
/// logs for a single test.
#[derive(Clone)]
pub struct LogWriter(pub Arc<Mutex<Vec<u8>>>);

impl LogWriter {
    pub fn contains(&self, needle: &str) -> bool {
        self.logs().contains(needle)
    }

    pub fn logs(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        print!("{}", String::from_utf8(buf.to_vec()).unwrap());
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

/// A mock response to be returned by the [`MockHandler`].
#[derive(Clone)]
pub struct MockRecord {
    /// The name server IP.  This is matched by the [`MockHandler`] against the destination address
    /// when deciding which response to return to the client.
    ns: IpAddr,
    /// The query name to match against
    query_name: Name,
    /// Query type
    query_type: RecordType,
    /// record-level TTL
    ttl: u32,
    /// record name
    record_name: Name,
    /// record data
    record_data: RData,
    /// The response section to place the record in
    section: MockResponseSection,
}

/// The section to place the record
#[derive(Clone)]
pub enum MockResponseSection {
    Answer,
    Additional,
    Authority,
}

/// Convenience functions for [`MockRecord`].  These should create records of the
/// specified type with a sensible TTL and section defaults.
impl MockRecord {
    pub fn a(server: IpAddr, rr_name: &Name, record_data: IpAddr) -> Self {
        let v4 = match record_data {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => panic!("a record does not support v6 address"),
        };

        Self {
            ns: server,
            ttl: 3600,
            query_name: rr_name.clone(),
            query_type: RecordType::A,
            record_name: rr_name.clone(),
            record_data: RData::A(A(v4)),
            section: MockResponseSection::Answer,
        }
    }

    pub fn ns(server: IpAddr, rr_name: &Name, ns_name: &Name) -> Self {
        Self {
            ns: server,
            ttl: 3600,
            query_name: rr_name.clone(),
            query_type: RecordType::NS,
            record_name: rr_name.clone(),
            record_data: RData::NS(NS(ns_name.clone())),
            section: MockResponseSection::Authority,
        }
    }

    pub fn soa(server: IpAddr, rr_name: &Name, mname: &Name, rname: &Name) -> Self {
        Self {
            ns: server,
            ttl: 0,
            query_name: rr_name.clone(),
            query_type: RecordType::SOA,
            record_name: rr_name.clone(),
            record_data: RData::SOA(SOA::new(mname.clone(), rname.clone(), 1, 1, 1, 1, 1)),
            section: MockResponseSection::Authority,
        }
    }

    pub fn with_query_name(mut self, query_name: &Name) -> Self {
        self.query_name = query_name.clone();
        self
    }

    pub fn with_query_type(mut self, query_type: RecordType) -> Self {
        self.query_type = query_type;
        self
    }

    pub fn with_section(mut self, section: MockResponseSection) -> Self {
        self.section = section;
        self
    }

    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
}

/// Request handling functionality that can be plugged into [`MockProvider`].
pub trait MockHandler {
    /// Takes in a request message and produces a response message.
    fn handle(&self, destination: IpAddr, protocol: ProtocolConfig, request: Message) -> Message;
}

/// Type alias for a closure that can modify the handler on a per-test basis.
pub type MockMutator = Box<dyn Fn(IpAddr, ProtocolConfig, &mut Message) + Send + Sync + 'static>;

/// Handler that stands in for multiple authoritative name servers, with specific canned responses.
pub struct MockNetworkHandler {
    responses: HashMap<IpAddr, HashMap<Query, Message>>,
    mutate: MockMutator,
}

impl MockNetworkHandler {
    /// Return a [`MockNetworkHandler`] that will respond to queries with [`MockRecord`] answers
    /// from responses.
    pub fn new(responses: Vec<MockRecord>) -> Self {
        let mut hashed_responses = HashMap::<IpAddr, HashMap<Query, Message>>::new();
        for response in responses {
            let query = Query::query(response.query_name.clone(), response.query_type);
            let mut message = Message::response(0, OpCode::Query);
            message.add_query(query.clone());
            message.set_authoritative(true);

            if let Some(ns) = hashed_responses.get(&response.ns) {
                if let Some(existing_message) = ns.get(&query) {
                    message = existing_message.clone();
                }
            }

            let record = Record::from_rdata(
                response.record_name.clone(),
                response.ttl,
                response.record_data,
            );

            match response.section {
                MockResponseSection::Additional => message.add_additional(record),
                MockResponseSection::Answer => message.add_answer(record),
                MockResponseSection::Authority => message.add_authority(record),
            };

            let query = message.queries()[0].clone();
            if let Some(ns) = hashed_responses.get_mut(&response.ns) {
                ns.insert(query, message);
            } else {
                let mut new_map = HashMap::new();
                new_map.insert(query, message);
                hashed_responses.insert(response.ns, new_map);
            }
        }

        Self {
            responses: hashed_responses,
            mutate: Box::new(
                |_destination: IpAddr, _protocol: ProtocolConfig, _message: &mut Message| {},
            ),
        }
    }

    pub fn with_mutation(mut self, mutate: MockMutator) -> Self {
        self.mutate = mutate;
        self
    }
}

impl MockHandler for MockNetworkHandler {
    fn handle(&self, destination: IpAddr, protocol: ProtocolConfig, request: Message) -> Message {
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
        response.take_queries();
        response.add_query(query.clone());

        (self.mutate)(destination, protocol, &mut response);
        response
    }
}

#[derive(Clone)]
pub struct MockProvider {
    handler: Arc<dyn MockHandler + Send + Sync>,
    new_connection_calls: Arc<Mutex<Vec<(IpAddr, ProtocolConfig)>>>,
    tokio_handle: TokioHandle,
}

impl MockProvider {
    pub fn new(handler: impl MockHandler + Send + Sync + 'static) -> Self {
        Self {
            handler: Arc::new(handler),
            new_connection_calls: Arc::new(Mutex::new(vec![])),
            tokio_handle: TokioHandle::default(),
        }
    }

    pub fn new_connection_calls(&self) -> Vec<(IpAddr, ProtocolConfig)> {
        self.new_connection_calls.lock().unwrap().clone()
    }

    pub fn count_new_connection_calls(&self, ip: IpAddr, protocol: ProtocolConfig) -> usize {
        self.new_connection_calls()
            .iter()
            .filter(|(ns_ip, proto)| *ns_ip == ip && *proto == protocol)
            .collect::<Vec<_>>()
            .len()
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
        self.new_connection_calls
            .lock()
            .unwrap()
            .push((server_addr.ip(), ProtocolConfig::Tcp));
        Box::pin(ready(Ok(MockTcpStream::new(
            self.handler.clone(),
            server_addr.ip(),
        ))))
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Udp>> + Send>> {
        self.new_connection_calls
            .lock()
            .unwrap()
            .push((server_addr.ip(), ProtocolConfig::Udp));
        Box::pin(ready(Ok(MockUdpSocket::new(self.handler.clone()))))
    }
}

pub struct MockUdpSocket {
    inner: Mutex<MockUdpSocketInner>,
    handler: Arc<dyn MockHandler + Send + Sync + 'static>,
}

pub struct MockUdpSocketInner {
    /// Response messages ready to be returned to the client.
    incoming_datagrams: VecDeque<(Message, SocketAddr)>,
    /// Waker from the last call to [`DnsUdpSocket::poll_recv_from()`], if it returned `Pending`.
    waker: Option<Waker>,
}

impl MockUdpSocket {
    pub fn new(handler: Arc<dyn MockHandler + Send + Sync + 'static>) -> Self {
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
        let response = self
            .handler
            .handle(target.ip(), ProtocolConfig::Udp, request);

        let mut guard = self.inner.lock().unwrap();
        guard.incoming_datagrams.push_back((response, target));

        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }

        Poll::Ready(Ok(buf.len()))
    }
}

pub struct MockTcpStream {
    inner: Mutex<MockTcpStreamInner>,
    destination: IpAddr,
    handler: Arc<dyn MockHandler + Send + Sync + 'static>,
}

struct MockTcpStreamInner {
    /// Buffered stream data, from the client to the mocked server.
    ///
    /// This is produced via [`AsyncWrite::poll_write()`], and consumed whenever a full message has
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
            let response = self
                .handler
                .handle(self.destination, ProtocolConfig::Tcp, request);

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
