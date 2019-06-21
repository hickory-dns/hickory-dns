#![allow(dead_code)]

extern crate chrono;
extern crate futures;
extern crate openssl;
extern crate rustls;
extern crate tokio;
extern crate tokio_timer;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_rustls;
extern crate trust_dns_server;

use std::fmt;
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::stream::{Fuse, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{finished, future, task, Async, Future, Poll};
use tokio_timer::Delay;

use trust_dns::client::ClientConnection;
use trust_dns::error::ClientResult;
use trust_dns::op::*;
use trust_dns::rr::dnssec::Signer;
use trust_dns::serialize::binary::*;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::{
    DnsClientStream, DnsMultiplexer, DnsMultiplexerConnect, DnsRequestSender, SerialMessage,
};
use trust_dns_proto::StreamHandle;

use trust_dns_server::authority::{Catalog, MessageRequest, MessageResponse};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

pub mod authority;
pub mod mock_client;
pub mod tls_client_connection;

#[allow(unused)]
pub struct TestClientStream {
    catalog: Arc<Mutex<Catalog>>,
    outbound_messages: Fuse<UnboundedReceiver<Vec<u8>>>,
}

#[allow(unused)]
impl TestClientStream {
    pub fn new(
        catalog: Arc<Mutex<Catalog>>,
    ) -> (
        Box<dyn Future<Item = Self, Error = ProtoError> + Send>,
        StreamHandle,
    ) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = StreamHandle::new(message_sender);

        let stream = Box::new(finished(TestClientStream {
            catalog,
            outbound_messages: outbound_messages.fuse(),
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

    fn into_inner(self) -> impl Future<Item = Vec<u8>, Error = ()> {
        future::poll_fn(move || {
            if self
                .message_ready
                .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let bytes: Vec<u8> = mem::replace(&mut self.buf.lock().unwrap(), vec![]);
                Ok(Async::Ready(bytes))
            } else {
                task::current().notify();
                Ok(Async::NotReady)
            }
        })
    }

    pub fn into_message(self) -> impl Future<Item = Message, Error = ()> {
        let bytes = self.into_inner();
        bytes.map(|b| {
            let mut decoder = BinDecoder::new(&b);
            Message::read(&mut decoder).expect("could not decode message")
        })
    }
}

impl ResponseHandler for TestResponseHandler {
    fn send_response(&self, response: MessageResponse) -> io::Result<()> {
        let buf = &mut self.buf.lock().unwrap();
        buf.clear();
        let mut encoder = BinEncoder::new(buf);
        response
            .destructive_emit(&mut encoder)
            .expect("could not encode");
        self.message_ready.store(true, Ordering::Release);
        Ok(())
    }
}

impl fmt::Display for TestClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "TestClientStream")
    }
}

impl DnsClientStream for TestClientStream {
    fn name_server_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 1234))
    }
}

impl Stream for TestClientStream {
    type Item = SerialMessage;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self
            .outbound_messages
            .poll()
            .map_err(|_| ProtoError::from("Server stopping due to interruption"))?
        {
            // already handled above, here to make sure the poll() pops the next message
            Async::Ready(Some(bytes)) => {
                let mut decoder = BinDecoder::new(&bytes);
                let src_addr = SocketAddr::from(([127, 0, 0, 1], 1234));

                let message = MessageRequest::read(&mut decoder).expect("could not decode message");
                let request = Request {
                    message,
                    src: src_addr,
                };

                dbg!("catalog handling request");
                let response_handler = TestResponseHandler::new();
                self.catalog
                    .lock()
                    .unwrap()
                    .handle_request(request, response_handler.clone())
                    .wait()
                    .unwrap();

                dbg!("catalog handled request");

                let buf = response_handler.into_inner().wait().unwrap();
                dbg!("catalog responded");

                Ok(Async::Ready(Some(SerialMessage::new(buf, src_addr))))
            }
            // now we get to drop through to the receives...
            // TODO: should we also return None if there are no more messages to send?
            _ => {
                task::current().notify();
                Ok(Async::NotReady)
            }
        }
    }
}

impl fmt::Debug for TestClientStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TestClientStream catalog")
    }
}

// need to do something with the message channel, otherwise the ClientFuture will think there
//  is no one listening to messages and shutdown...
#[allow(dead_code)]
pub struct NeverReturnsClientStream {
    timeout: Delay,
    outbound_messages: Fuse<UnboundedReceiver<Vec<u8>>>,
}

#[allow(dead_code)]
impl NeverReturnsClientStream {
    pub fn new() -> (
        Box<dyn Future<Item = Self, Error = ProtoError> + Send>,
        StreamHandle,
    ) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = StreamHandle::new(message_sender);

        let stream = Box::new(finished(NeverReturnsClientStream {
            timeout: Delay::new(Instant::now() + Duration::from_secs(1)),
            outbound_messages: outbound_messages.fuse(),
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
    fn name_server_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 53))
    }
}

impl Stream for NeverReturnsClientStream {
    type Item = SerialMessage;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        println!("still not returning");

        // poll the timer forever...
        if let Ok(Async::NotReady) = self.timeout.poll() {
            return Ok(Async::NotReady);
        }

        self.timeout.reset(Instant::now() + Duration::from_secs(1));

        match self.timeout.poll() {
            Ok(Async::NotReady) => Ok(Async::NotReady),
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

impl ClientConnection for NeverReturnsClientConnection {
    type Sender = DnsMultiplexer<NeverReturnsClientStream, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<
        Box<dyn Future<Item = NeverReturnsClientStream, Error = ProtoError> + Send>,
        NeverReturnsClientStream,
        Signer,
    >;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (client_stream, handle) = NeverReturnsClientStream::new();

        DnsMultiplexer::new(Box::new(client_stream), Box::new(handle), signer)
    }
}
