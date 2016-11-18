use std::io;
use std::net::SocketAddr;

use futures::{Async, Poll};
use futures::stream::Stream;

use trust_dns::BufferStreamHandle;
use trust_dns::op::Message;
use trust_dns::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};

pub struct Request{
  pub message: Message,
  pub src: SocketAddr,
}

/// ReqeustStreams take in bytes, deserialize and pass on Messages
///
/// This wraps underlying byte buffers, e.g. UDP and TCP streams. A request from the underlying
///  stream deserialize and then have the Catalog determine the authrority to use to return a
///  result. The expectation is that from a stream of messages and src addresses, a result set
///  can be returned.
pub struct RequestStream<S> {
  stream: S,
  stream_handle: BufferStreamHandle,
}

impl<S> RequestStream<S> {
  pub fn new(stream: S, stream_handle: BufferStreamHandle) -> Self {
    RequestStream{ stream: stream, stream_handle: stream_handle }
  }
}

impl<S> Stream for RequestStream<S>
where S: Stream<Item=(Vec<u8>, SocketAddr), Error=io::Error> {
  type Item = (Request, ResponseHandle);
  type Error = io::Error;

  fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
    loop {
      match try_ready!(self.stream.poll()) {
        None => return Ok(Async::Ready(None)),
        Some((buffer, addr)) => {
          // decode any messages that are ready
          let mut decoder = BinDecoder::new(&buffer);
          match Message::read(&mut decoder) {
            Ok(message) => {
              let request = Request{ message: message, src: addr};
              let response_handle = ResponseHandle{ dst: addr, stream_handle: self.stream_handle.clone() };
              return Ok(Async::Ready(Some((request, response_handle))));
            },
            // on errors, we will loop around and see if more are ready
            Err(e) => {
              // FIXME: respond with an error here? right now this will drop and ignore the request
              debug!("bad message format: {}", e);
            },
          }
        },
      }
    }
  }
}

pub struct ResponseHandle {
  dst: SocketAddr,
  stream_handle: BufferStreamHandle, // FIXME, needs to be genric with TcpListener...
}

impl ResponseHandle {
  pub fn send(&self, response: Message) -> io::Result<()> {
    let mut buffer = Vec::with_capacity(512);
    let encode_result = {
      let mut encoder: BinEncoder = BinEncoder::new(&mut buffer);
      response.emit(&mut encoder)
    };

    try!(encode_result.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("error encoding message: {}", e))));

    self.stream_handle.send((buffer, self.dst))
  }
}
