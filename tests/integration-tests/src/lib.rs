#![allow(dead_code)]
#![allow(clippy::dbg_macro)]

use std::{
    fmt, io, mem,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use futures::{
    future,
    stream::{Stream, StreamExt},
    Future, FutureExt,
};
use tokio::time::{Duration, Instant, Sleep};

use trust_dns_client::{
    client::{ClientConnection, Signer},
    error::ClientResult,
    op::*,
    serialize::binary::*,
};
use trust_dns_proto::{
    error::ProtoError,
    rr::Record,
    xfer::{DnsClientStream, DnsMultiplexer, DnsMultiplexerConnect, SerialMessage, StreamReceiver},
    BufDnsStreamHandle, TokioTime,
};
use trust_dns_server::{
    authority::{Catalog, MessageRequest, MessageResponse},
    server::{Protocol, Request, RequestHandler, ResponseHandler, ResponseInfo},
};

pub mod example_authority;
pub mod mock_client;
#[cfg(feature = "dns-over-rustls")]
pub mod tls_client_connection;

#[allow(unused)]
pub struct TestClientStream {
    catalog: Arc<Mutex<Catalog>>,
    outbound_messages: StreamReceiver,
}

#[allow(unused)]
impl TestClientStream {
    #[allow(clippy::type_complexity)]
    pub fn new(
        catalog: Arc<Mutex<Catalog>>,
    ) -> (
        Pin<Box<dyn Future<Output = Result<Self, ProtoError>> + Send>>,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(([0, 0, 0, 0], 0).into());

        let stream = Box::pin(future::ok(TestClientStream {
            catalog,
            outbound_messages,
        }));

        (stream, message_sender)
    }
}

#[derive(Clone, Default)]
pub struct TestResponseHandler {
    message_ready: Arc<AtomicBool>,
    buf: Arc<Mutex<Vec<u8>>>,
}

impl TestResponseHandler {
    pub fn new() -> Self {
        let buf = Arc::new(Mutex::new(Vec::with_capacity(512)));
        let message_ready = Arc::new(AtomicBool::new(false));
        TestResponseHandler { message_ready, buf }
    }

    fn into_inner(self) -> impl Future<Output = Vec<u8>> {
        future::poll_fn(move |_| {
            if self
                .message_ready
                .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let bytes: Vec<u8> = mem::take(&mut self.buf.lock().unwrap());
                Poll::Ready(bytes)
            } else {
                Poll::Pending
            }
        })
    }

    pub fn into_message(self) -> impl Future<Output = Message> {
        let bytes = self.into_inner();
        bytes.map(|b| {
            let mut decoder = BinDecoder::new(&b);
            Message::read(&mut decoder).expect("could not decode message")
        })
    }
}

#[async_trait::async_trait]
impl ResponseHandler for TestResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let buf = &mut self.buf.lock().unwrap();
        buf.clear();
        let mut encoder = BinEncoder::new(buf);
        let info = response
            .destructive_emit(&mut encoder)
            .expect("could not encode");
        self.message_ready.store(true, Ordering::Release);
        Ok(info)
    }
}

impl fmt::Display for TestClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "TestClientStream")
    }
}

impl DnsClientStream for TestClientStream {
    type Time = TokioTime;

    fn name_server_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 1234))
    }
}

impl Stream for TestClientStream {
    type Item = Result<SerialMessage, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        use futures::executor::block_on;

        match self.outbound_messages.next().poll_unpin(cx) {
            // already handled above, here to make sure the poll() pops the next message
            Poll::Ready(Some(bytes)) => {
                let mut decoder = BinDecoder::new(bytes.bytes());
                let src_addr = SocketAddr::from(([127, 0, 0, 1], 1234));

                let message = MessageRequest::read(&mut decoder).expect("could not decode message");
                let request = Request::new(message, src_addr, Protocol::Udp);

                let response_handler = TestResponseHandler::new();
                block_on(
                    self.catalog
                        .lock()
                        .unwrap()
                        .handle_request(&request, response_handler.clone()),
                );

                let buf = block_on(response_handler.into_inner());
                Poll::Ready(Some(Ok(SerialMessage::new(buf, src_addr))))
            }
            // now we get to drop through to the receives...
            Poll::Ready(None) => Poll::Ready(None),
            // TODO: should we also return None if there are no more messages to send?
            Poll::Pending => {
                //dbg!("PENDING");
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl fmt::Debug for TestClientStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TestClientStream catalog")
    }
}

// need to do something with the message channel, otherwise the AsyncClient will think there
//  is no one listening to messages and shutdown...
#[allow(dead_code)]
pub struct NeverReturnsClientStream {
    timeout: Pin<Box<Sleep>>,
    outbound_messages: StreamReceiver,
}

#[allow(dead_code)]
impl NeverReturnsClientStream {
    #[allow(clippy::type_complexity)]
    pub fn new() -> (
        Pin<Box<dyn Future<Output = Result<Self, ProtoError>> + Send>>,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(([0, 0, 0, 0], 0).into());

        let stream = Box::pin(future::lazy(|_| {
            Ok(NeverReturnsClientStream {
                timeout: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
                outbound_messages,
            })
        }));

        (stream, message_sender)
    }
}

impl fmt::Display for NeverReturnsClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "NeverReturnsClientStream")
    }
}

impl DnsClientStream for NeverReturnsClientStream {
    type Time = TokioTime;

    fn name_server_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 53))
    }
}

impl Stream for NeverReturnsClientStream {
    type Item = Result<SerialMessage, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // poll the timer forever...
        if self.timeout.poll_unpin(cx).is_pending() {
            return Poll::Pending;
        }

        self.timeout
            .as_mut()
            .reset(Instant::now() + Duration::from_secs(1));

        match self.timeout.poll_unpin(cx) {
            Poll::Pending => Poll::Pending,
            _ => panic!("timeout fired early"),
        }
    }
}

impl fmt::Debug for NeverReturnsClientStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TestClientStream catalog")
    }
}

#[allow(dead_code)]
pub struct NeverReturnsClientConnection {}

impl NeverReturnsClientConnection {
    pub fn new() -> ClientResult<Self> {
        Ok(NeverReturnsClientConnection {})
    }
}

#[allow(clippy::type_complexity)]
impl ClientConnection for NeverReturnsClientConnection {
    type Sender = DnsMultiplexer<NeverReturnsClientStream, Signer>;
    type SenderFuture = DnsMultiplexerConnect<
        Pin<Box<dyn Future<Output = Result<NeverReturnsClientStream, ProtoError>> + Send>>,
        NeverReturnsClientStream,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (client_stream, handle) = NeverReturnsClientStream::new();

        DnsMultiplexer::new(Box::pin(client_stream), handle, signer)
    }
}
