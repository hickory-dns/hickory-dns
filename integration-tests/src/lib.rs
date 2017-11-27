#![allow(dead_code)]

extern crate chrono;
extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_server;

use std::sync::Arc;
use std::fmt;
use std::io;

use futures::{finished, Async, Future, Poll};
use futures::stream::{Fuse, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::task;
use tokio_core::reactor::Handle;

use trust_dns::error::{ClientError, ClientResult};
use trust_dns::client::ClientConnection;
use trust_dns::op::*;
use trust_dns::serialize::binary::*;
use trust_dns_proto::{DnsStreamHandle, StreamHandle};
use trust_dns_proto::error::FromProtoError;

use trust_dns_server::authority::Catalog;
use trust_dns_server::server::{Request, RequestHandler};

pub mod authority;
pub mod mock_client;

#[allow(unused)]
pub struct TestClientStream {
    catalog: Arc<Catalog>,
    outbound_messages: Fuse<UnboundedReceiver<Vec<u8>>>,
}

#[allow(unused)]
impl TestClientStream {
    pub fn new<E: FromProtoError>(
        catalog: Arc<Catalog>,
    ) -> (Box<Future<Item = Self, Error = io::Error>>, StreamHandle<E>) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = StreamHandle::new(message_sender);

        let stream: Box<Future<Item = TestClientStream, Error = io::Error>> =
            Box::new(finished(TestClientStream {
                catalog: catalog,
                outbound_messages: outbound_messages.fuse(),
            }));

        (stream, message_sender)
    }
}

impl Stream for TestClientStream {
    type Item = Vec<u8>;
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

                let message = Message::read(&mut decoder).expect("could not decode message");
                let request = Request {
                    message: message,
                    src: "127.0.0.1:1234"
                        .parse()
                        .expect("cannot parse host and port"),
                };
                let response = self.catalog.handle_request(&request);

                let mut buf = Vec::with_capacity(512);
                {
                    let mut encoder = BinEncoder::new(&mut buf);
                    response.emit(&mut encoder).expect("could not encode");
                }

                Ok(Async::Ready(Some(buf)))
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
    outbound_messages: Fuse<UnboundedReceiver<Vec<u8>>>,
}

#[allow(dead_code)]
impl NeverReturnsClientStream {
    pub fn new() -> (
        Box<Future<Item = Self, Error = io::Error>>,
        StreamHandle<ClientError>,
    ) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = StreamHandle::new(message_sender);

        let stream: Box<Future<Item = NeverReturnsClientStream, Error = io::Error>> =
            Box::new(finished(NeverReturnsClientStream {
                outbound_messages: outbound_messages.fuse(),
            }));

        (stream, message_sender)
    }
}

impl Stream for NeverReturnsClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // always not ready...
        task::current().notify();
        Ok(Async::NotReady)
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
        _: &Handle,
    ) -> ClientResult<
        (
            Box<Future<Item = Self::MessageStream, Error = io::Error>>,
            Box<DnsStreamHandle<Error = ClientError>>,
        ),
    > {
        let (client_stream, handle) = NeverReturnsClientStream::new();

        Ok((client_stream, Box::new(handle)))
    }
}
