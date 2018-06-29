//! DNS high level transit implimentations.
//!
//! Primarily there are two types in this module of interest, the `DnsFuture` type and the `DnsHandle` type. `DnsFuture` can be thought of as the state machine responsible for sending and receiving DNS messages. `DnsHandle` is the type given to API users of the `trust-dns-proto` library to send messages into the `DnsFuture` for delivery. Finally there is the `DnsRequest` type. This allows for customizations, through `DnsReqeustOptions`, to the delivery of messages via a `DnsFuture`.
//!
//! TODO: this module needs some serious refactoring and normalization.

use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;

use error::*;
use futures::sync::mpsc::{SendError, UnboundedSender};
use futures::sync::oneshot;
use futures::{future, Async, Flatten, Future, IntoFuture, Poll};
use op::Message;

pub mod dns_future;
pub mod dns_handle;
pub mod dns_request;
pub mod dns_response;
mod dns_stream;
pub mod retry_dns_handle;
#[cfg(feature = "dnssec")]
pub mod secure_dns_handle;
mod serial_message;

pub use self::dns_future::DnsFuture;
pub use self::dns_handle::{BasicDnsHandle, DnsHandle, DnsStreamHandle, StreamHandle};
pub use self::dns_request::{DnsRequest, DnsRequestOptions};
pub use self::dns_response::DnsResponse;
pub use self::dns_stream::{DnsStream, DnsStreamConnect};
pub use self::retry_dns_handle::RetryDnsHandle;
#[cfg(feature = "dnssec")]
pub use self::secure_dns_handle::SecureDnsHandle;
pub use self::serial_message::SerialMessage;

/// Ignores the result of a send operation and logs and ignores errors
fn ignore_send<M, E: Debug>(result: Result<M, E>) {
    if let Err(error) = result {
        warn!("error notifying wait, possible future leak: {:?}", error);
    }
}

// TODO: change to Sink
/// A sender to which serialized DNS Messages can be sent
#[derive(Clone)]
pub struct BufStreamHandle<E>
where
    E: FromProtoError,
{
    sender: UnboundedSender<SerialMessage>,
    phantom: PhantomData<E>,
}

impl<E> BufStreamHandle<E>
where
    E: FromProtoError,
{
    /// Constructs a new BufStreamHandle with the associated ProtoError
    pub fn new(sender: UnboundedSender<SerialMessage>) -> Self {
        BufStreamHandle {
            sender,
            phantom: PhantomData::<E>,
        }
    }

    /// see [`futures::sync::mpsc::UnboundedSender`]
    pub fn unbounded_send(&self, msg: SerialMessage) -> Result<(), SendError<SerialMessage>> {
        self.sender.unbounded_send(msg)
    }
}

// TODO: change to Sink
/// A sender to which a Message can be sent
pub type MessageStreamHandle = UnboundedSender<Message>;

/// A buffering stream bound to a `SocketAddr`
pub struct BufDnsStreamHandle<E>
where
    E: FromProtoError,
{
    name_server: SocketAddr,
    sender: BufStreamHandle<E>,
}

impl<E> BufDnsStreamHandle<E>
where
    E: FromProtoError,
{
    /// Constructs a new Buffered Stream Handle, used for sending data to the DNS peer.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the address of the DNS server
    /// * `sender` - the handle being used to send data to the server
    pub fn new(name_server: SocketAddr, sender: BufStreamHandle<E>) -> Self {
        BufDnsStreamHandle {
            name_server: name_server,
            sender: sender,
        }
    }
}

impl<E> DnsStreamHandle for BufDnsStreamHandle<E>
where
    E: FromProtoError,
{
    type Error = E;

    fn send(&mut self, buffer: Vec<u8>) -> Result<(), E> {
        let name_server: SocketAddr = self.name_server;
        let sender: &mut _ = &mut self.sender;
        sender
            .sender
            .unbounded_send(SerialMessage::new(buffer, name_server))
            .map_err(|e| E::from(format!("mpsc::SendError {}", e).into()))
    }
}

// TODO: expose the Sink trait for this?
/// A sender to which serialized DNS Messages can be sent
pub struct SerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    sender: UnboundedSender<OneshotSerialRequest<F>>,
}

impl<F> SerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    /// Constructs a new BufStreamHandle with the associated ProtoError
    pub fn new(sender: UnboundedSender<OneshotSerialRequest<F>>) -> Self {
        SerialMessageStreamHandle { sender }
    }

    /// see [`futures::sync::mpsc::UnboundedSender`]
    pub fn unbounded_send(
        &self,
        msg: OneshotSerialRequest<F>,
    ) -> Result<(), SendError<OneshotSerialRequest<F>>> {
        self.sender.unbounded_send(msg)
    }
}

impl<F> Clone for SerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    fn clone(&self) -> Self {
        SerialMessageStreamHandle {
            sender: self.sender.clone(),
        }
    }
}

/// Types that implement this are capable of sending a serialized DNS message on a stream
pub trait SerialMessageSender: Clone + Send {
    /// A future that resolves to a response serial message
    type SerialResponse: Future<Item = DnsResponse, Error = ProtoError> + Send;

    /// Send a message, and return a future of the response
    ///
    /// # Return
    ///
    /// A future which will resolve to a SerialMessage response
    fn send_message(&mut self, message: SerialMessage) -> Self::SerialResponse;
}

pub struct BufSerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    name_server: SocketAddr,
    sender: SerialMessageStreamHandle<F>,
}

impl<F> BufSerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    pub fn new(name_server: SocketAddr, sender: SerialMessageStreamHandle<F>) -> Self {
        BufSerialMessageStreamHandle {
            name_server,
            sender,
        }
    }
}

impl<F> Clone for BufSerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    fn clone(&self) -> Self {
        BufSerialMessageStreamHandle {
            name_server: self.name_server.clone(),
            sender: self.sender.clone(),
        }
    }
}

impl<F> DnsHandle for BufSerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send + 'static,
{
    type Error = ProtoError;
    type Response = OneshotDnsResponseReceiver<F>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let name_server: SocketAddr = self.name_server;
        // FIXME: need to do something with this error
        let bytes: Vec<u8> = request.into().to_vec().expect("could not serialize");
        let serial_message = SerialMessage::new(bytes, name_server);
        let (request, oneshot) = OneshotSerialRequest::oneshot(serial_message);
        self.sender
            .unbounded_send(request)
            .expect("could not send!");
        //.map_err(|e| format!("mpsc::SendError {}", e).into())?;

        OneshotDnsResponseReceiver::Receiver(oneshot)
    }
}

/// A OneshotSerialRequest createa a channel for a response to message
pub struct OneshotSerialRequest<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    serial_request: SerialMessage,
    sender_for_response: oneshot::Sender<F>,
}

impl<F> OneshotSerialRequest<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    fn oneshot(serial_request: SerialMessage) -> (OneshotSerialRequest<F>, oneshot::Receiver<F>) {
        let (sender_for_response, receiver) = oneshot::channel();

        (
            OneshotSerialRequest {
                serial_request,
                sender_for_response,
            },
            receiver,
        )
    }

    fn unwrap(self) -> (SerialMessage, OneshotSerialResponse<F>) {
        (
            self.serial_request,
            OneshotSerialResponse(self.sender_for_response),
        )
    }
}

struct OneshotSerialResponse<F>(oneshot::Sender<F>)
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send;

impl<F> OneshotSerialResponse<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    fn send_response(self, serial_response: F) -> Result<(), F> {
        self.0.send(serial_response)
    }
}

pub enum OneshotDnsResponseReceiver<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    Receiver(oneshot::Receiver<F>),
    Received(F),
}

impl<F> Future for OneshotDnsResponseReceiver<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    type Item = <F as Future>::Item;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let future;
            match self {
                OneshotDnsResponseReceiver::Receiver(ref mut receiver) => {
                    future = try_ready!(
                        receiver
                            .poll()
                            .map_err(|_| ProtoError::from("receiver was canceled"))
                    );
                }
                OneshotDnsResponseReceiver::Received(ref mut future) => return future.poll(),
            }

            *self = OneshotDnsResponseReceiver::Received(future);
        }
    }
}
