use std::io;
use std::net::SocketAddr;

use futures::{Async, Future, Poll};

use error::ProtoError;
use xfer::{DnsRequest, DnsResponse, SerialMessage, SerialMessageSender};

pub trait DnsClient {
    type Response: Future<Item = DnsResponse, Error = ProtoError>;

    fn send_message(&mut self, dest: SocketAddr, message: DnsRequest) -> Self::Response;
}

impl<S, R> DnsClient for S
where
    S: SerialMessageSender<SerialResponse = R>,
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    type Response = MessageFromSerialFuture<R>;

    fn send_message(&mut self, dest: SocketAddr, message: DnsRequest) -> Self::Response {
        // FIXME: change signature to Result? or pass into the Future?
        let bytes = message.to_vec().expect("serial message failed");
        let message: SerialMessage = SerialMessage::new(bytes, dest);
        MessageFromSerialFuture(self.send_message(message))
    }
}

pub struct MessageFromSerialFuture<R>(R)
where
    R: Future<Item = SerialMessage, Error = io::Error> + Send;

impl<R> Future for MessageFromSerialFuture<R>
where
    R: Future<Item = SerialMessage, Error = io::Error> + Send,
{
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let serial_message = try_ready!(self.0.poll());

        let addr = serial_message.addr();
        let message = serial_message.to_message()?;

        Ok(Async::Ready(DnsResponse::from(message)))
    }
}
