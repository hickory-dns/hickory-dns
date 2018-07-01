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
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::stream::{Fuse, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::task;
use futures::{finished, Async, Future, Poll};
use tokio_timer::Delay;

use trust_dns::client::ClientConnection;
use trust_dns::error::{ClientError, ClientResult};
use trust_dns::op::*;
use trust_dns::serialize::binary::*;
use trust_dns_proto::error::FromProtoError;
use trust_dns_proto::xfer::{DnsClientStream, SerialMessage};
use trust_dns_proto::{DnsStreamHandle, StreamHandle};

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
    pub fn new<E: FromProtoError + Send>(
        catalog: Arc<Mutex<Catalog>>,
    ) -> (
        Box<Future<Item = Self, Error = io::Error> + Send>,
        StreamHandle<E>,
    ) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = StreamHandle::new(message_sender);

        let stream = Box::new(finished(TestClientStream {
            catalog: catalog,
            outbound_messages: outbound_messages.fuse(),
        }));

        (stream, message_sender)
    }
}

#[derive(Clone)]
pub struct TestResponseHandler {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl TestResponseHandler {
    pub fn new() -> Self {
        let buf = Arc::new(Mutex::new(Vec::with_capacity(512)));
        TestResponseHandler { buf }
    }

    pub fn into_inner(self) -> Vec<u8> {
        Arc::try_unwrap(self.buf).unwrap().into_inner().unwrap()
    }

    pub fn into_message(self) -> Message {
        let bytes = self.into_inner();
        let mut decoder = BinDecoder::new(&bytes);
        Message::read(&mut decoder).expect("could not decode message")
    }
}

impl ResponseHandler for TestResponseHandler {
    fn send(self, response: MessageResponse) -> io::Result<()> {
        let buf = &mut self.buf.lock().unwrap();
        let mut encoder = BinEncoder::new(buf);
        response
            .destructive_emit(&mut encoder)
            .expect("could not encode");
        Ok(())
    }
}

impl DnsClientStream for TestClientStream {
    fn name_server_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 1234))
    }
}

impl Stream for TestClientStream {
    type Item = SerialMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.outbound_messages.poll().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Interrupted,
                "Server stopping due to interruption",
            )
        })? {
            // already handled above, here to make sure the poll() pops the next message
            Async::Ready(Some(bytes)) => {
                let mut decoder = BinDecoder::new(&bytes);
                let src_addr = SocketAddr::from(([127, 0, 0, 1], 1234));

                let message = MessageRequest::read(&mut decoder).expect("could not decode message");
                let request = Request {
                    message: message,
                    src: src_addr,
                };

                let response_handler = TestResponseHandler::new();
                self.catalog
                    .lock()
                    .unwrap()
                    .handle_request(&request, response_handler.clone())
                    .unwrap();

                let buf = response_handler.into_inner();
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
        Box<Future<Item = Self, Error = io::Error> + Send>,
        StreamHandle<ClientError>,
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

impl DnsClientStream for NeverReturnsClientStream {
    fn name_server_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 53))
    }
}

impl Stream for NeverReturnsClientStream {
    type Item = SerialMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        println!("still not returning");

        // poll the timer forever...
        match self.timeout.poll() {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            _ => (),
        }

        self.timeout.reset(Instant::now() + Duration::from_secs(1));

        match self.timeout.poll() {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
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
    type MessageStream = NeverReturnsClientStream;

    fn new_stream(
        &self,
    ) -> ClientResult<(
        Box<Future<Item = Self::MessageStream, Error = io::Error> + Send>,
        Box<DnsStreamHandle<Error = ClientError> + Send>,
    )> {
        let (client_stream, handle) = NeverReturnsClientStream::new();

        Ok((client_stream, Box::new(handle)))
    }
}
