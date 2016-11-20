use std::fmt;
use std::io;

use futures::{Async, Future, finished, Poll};
use futures::stream::{Fuse, Stream};
use futures::task::park;
use tokio_core::reactor::*;
use tokio_core::channel::*;

use trust_dns::client::ClientStreamHandle;
use trust_dns::op::*;
use trust_dns::serialize::binary::*;

use trust_dns_server::authority::Catalog;

pub struct TestClientStream {
  catalog: Catalog,
  outbound_messages: Fuse<Receiver<Vec<u8>>>,
}

impl TestClientStream {
  pub fn new(catalog: Catalog, loop_handle: Handle) -> (Box<Future<Item=Self, Error=io::Error>>, Box<ClientStreamHandle>) {
    let (message_sender, outbound_messages) = channel(&loop_handle).expect("somethings wrong with the event loop");

    let stream: Box<Future<Item=TestClientStream, Error=io::Error>> = Box::new(finished(
      TestClientStream { catalog: catalog, outbound_messages: outbound_messages.fuse() }
    ));

    (stream, Box::new(message_sender))
  }
}

impl Stream for TestClientStream {
  type Item = Vec<u8>;
  type Error = io::Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    match try!(self.outbound_messages.poll()) {
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
      },
      // now we get to drop through to the receives...
      // TODO: should we also return None if there are no more messages to send?
      _ => {
        park().unpark();
        Ok(Async::NotReady)
      },
    }
  }
}

impl fmt::Debug for TestClientStream {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "TestClientStream catalog")
  }
}
