#![allow(dead_code)]


use std::fmt;
use std::io;

use futures::{Async, Future, finished, Poll};
use futures::stream::{Fuse, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::task::park;
use tokio_core::reactor::Core;

use trust_dns::error::ClientResult;
use trust_dns::client::{ClientConnection, ClientStreamHandle};
use trust_dns::op::*;
use trust_dns::serialize::binary::*;

use trust_dns_server::authority::Catalog;

pub mod authority;
pub mod server_harness;

#[allow(unused)]
pub struct TestClientStream {
    catalog: Catalog,
    outbound_messages: Fuse<UnboundedReceiver<Vec<u8>>>,
}

#[allow(unused)]
impl TestClientStream {
    pub fn new(catalog: Catalog)
               -> (Box<Future<Item = Self, Error = io::Error>>, Box<ClientStreamHandle>) {
        let (message_sender, outbound_messages) = unbounded();

        let stream: Box<Future<Item = TestClientStream, Error = io::Error>> =
            Box::new(finished(TestClientStream {
                catalog: catalog,
                outbound_messages: outbound_messages.fuse(),
            }));

        (stream, Box::new(message_sender))
    }
}

impl Stream for TestClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try!(self.outbound_messages.poll().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted,
                           "Server stopping due to interruption")
        })) {
            // already handled above, here to make sure the poll() pops the next message
            Async::Ready(Some(bytes)) => {
                let mut decoder = BinDecoder::new(&bytes);

                let message = Message::read(&mut decoder).expect("could not decode message");
                let response = self.catalog.handle_request(&message);

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
                park().unpark();
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
    pub fn new() -> (Box<Future<Item = Self, Error = io::Error>>, Box<ClientStreamHandle>) {
        let (message_sender, outbound_messages) = unbounded();

        let stream: Box<Future<Item = NeverReturnsClientStream, Error = io::Error>> =
            Box::new(finished(NeverReturnsClientStream {
                                  outbound_messages: outbound_messages.fuse(),
                              }));

        (stream, Box::new(message_sender))
    }
}

impl Stream for NeverReturnsClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // always not ready...
        park().unpark();
        Ok(Async::NotReady)
    }
}

impl fmt::Debug for NeverReturnsClientStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TestClientStream catalog")
    }
}

#[allow(dead_code)]
pub struct NeverReturnsClientConnection {
    io_loop: Core,
    client_stream: Box<Future<Item = NeverReturnsClientStream, Error = io::Error>>,
    client_stream_handle: Box<ClientStreamHandle>,
}

impl NeverReturnsClientConnection {
    pub fn new() -> ClientResult<Self> {
        let io_loop = try!(Core::new());
        let (client_stream, handle) = NeverReturnsClientStream::new();

        Ok(NeverReturnsClientConnection {
               io_loop: io_loop,
               client_stream: client_stream,
               client_stream_handle: handle,
           })
    }
}

impl ClientConnection for NeverReturnsClientConnection {
    type MessageStream = NeverReturnsClientStream;

    fn unwrap
        (self)
         -> (Core,
             Box<Future<Item = Self::MessageStream, Error = io::Error>>,
             Box<ClientStreamHandle>) {
        (self.io_loop, self.client_stream, self.client_stream_handle)
    }
}