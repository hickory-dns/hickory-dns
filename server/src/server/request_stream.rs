use std::io;
use std::net::SocketAddr;

use futures::{Async, Poll, Stream};

use trust_dns::BufStreamHandle;
use trust_dns::error::ClientError;
use trust_dns::op::Message;
use trust_dns::serialize::binary::{BinDecoder, BinEncoder, BinSerializable};

/// An incoming request to the DNS catalog
pub struct Request {
    /// Message with the associated query or update data
    pub message: Message,
    /// Source address of the Client
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
    stream_handle: BufStreamHandle<ClientError>,
}

impl<S> RequestStream<S> {
    /// Creates a new RequestStream
    ///
    /// # Arguments
    /// * `stream` - Stream from which requests will be read
    /// * `stream_handle` - Handle to which responses will be posted
    pub fn new(stream: S, stream_handle: BufStreamHandle<ClientError>) -> Self {
        RequestStream {
            stream: stream,
            stream_handle: stream_handle,
        }
    }
}

impl<S> Stream for RequestStream<S>
where
    S: Stream<Item = (Vec<u8>, SocketAddr), Error = io::Error>,
{
    type Item = (Request, ResponseHandle);
    type Error = io::Error;

    /// Polls the underlying Stream for readyness.
    ///
    /// # Returns
    /// When `Async::Ready(Some(_))` is returned, it contains the deserialized request and a handle
    ///  back to the underlying stream to which a response can be sent.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match try_ready!(self.stream.poll()) {
                None => return Ok(Async::Ready(None)),
                Some((buffer, addr)) => {
                    // TODO: rather than decoding the message here, this RequestStream should instead
                    //       forward the request to another sender such that we could pull serialization off
                    //       the IO thread.
                    // decode any messages that are ready
                    let mut decoder = BinDecoder::new(&buffer);
                    match Message::read(&mut decoder) {
                        Ok(message) => {
                            info!(
                                "request: {} recieved from: {} len: {}",
                                message.id(),
                                addr,
                                buffer.len()
                            );
                            let request = Request {
                                message: message,
                                src: addr,
                            };
                            let response_handle = ResponseHandle {
                                dst: addr,
                                stream_handle: self.stream_handle.clone(),
                            };
                            return Ok(Async::Ready(Some((request, response_handle))));
                        }
                        // on errors, we will loop around and see if more are ready
                        Err(e) => {
                            // FIXME: respond with an error here? right now this will drop and ignore the request
                            warn!(
                                "bad message from: {} len: {}: err: {} ",
                                addr,
                                buffer.len(),
                                e
                            );
                        }
                    }
                }
            }
        }
    }
}

/// A handler for wraping a BufStreamHandle, which will properly serialize the message and add the
///  associated destination.
pub struct ResponseHandle {
    dst: SocketAddr,
    stream_handle: BufStreamHandle<ClientError>,
}

impl ResponseHandle {
    /// Serializes and sends a message to to the wrapped handle
    pub fn send(&mut self, response: Message) -> io::Result<()> {
        debug!("sending message: {}", response.id());
        let mut buffer = Vec::with_capacity(512);
        let encode_result = {
            let mut encoder: BinEncoder = BinEncoder::new(&mut buffer);
            response.emit(&mut encoder)
        };

        encode_result.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("error encoding message: {}", e),
            )
        })?;

        self.stream_handle
            .unbounded_send((buffer, self.dst))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unknown"))
    }
}
