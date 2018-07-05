//! DNS high level transit implimentations.
//!
//! Primarily there are two types in this module of interest, the `DnsFuture` type and the `DnsHandle` type. `DnsFuture` can be thought of as the state machine responsible for sending and receiving DNS messages. `DnsHandle` is the type given to API users of the `trust-dns-proto` library to send messages into the `DnsFuture` for delivery. Finally there is the `DnsRequest` type. This allows for customizations, through `DnsReqeustOptions`, to the delivery of messages via a `DnsFuture`.
//!
//! TODO: this module needs some serious refactoring and normalization.

use std::fmt::{Debug, Display};
use std::io;
use std::net::SocketAddr;

use error::*;
use futures::sync::mpsc::{SendError, UnboundedSender};
use futures::sync::oneshot;
use futures::{Future, Poll, Stream};
use op::Message;

mod dns_exchange;
pub mod dns_future;
pub mod dns_handle;
pub mod dns_request;
pub mod dns_response;
pub mod retry_dns_handle;
#[cfg(feature = "dnssec")]
pub mod secure_dns_handle;
mod serial_message;

pub use self::dns_exchange::{DnsExchange, DnsExchangeConnect};
pub use self::dns_future::{DnsFuture, DnsFutureSerialResponse};
pub use self::dns_handle::{BasicDnsHandle, DnsHandle, DnsStreamHandle, StreamHandle};
pub use self::dns_request::{DnsRequest, DnsRequestOptions};
pub use self::dns_response::DnsResponse;
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

/// A non-multiplexed stream of Serialized DNS messages
pub trait DnsClientStream:
    Stream<Item = SerialMessage, Error = io::Error> + Display + Send
{
    /// The remote name server address
    fn name_server_addr(&self) -> SocketAddr;
}

// TODO: change to Sink
/// A sender to which serialized DNS Messages can be sent
#[derive(Clone)]
pub struct BufStreamHandle {
    sender: UnboundedSender<SerialMessage>,
}

impl BufStreamHandle {
    /// Constructs a new BufStreamHandle with the associated ProtoError
    pub fn new(sender: UnboundedSender<SerialMessage>) -> Self {
        BufStreamHandle { sender }
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
pub struct BufDnsStreamHandle {
    name_server: SocketAddr,
    sender: BufStreamHandle,
}

impl BufDnsStreamHandle {
    /// Constructs a new Buffered Stream Handle, used for sending data to the DNS peer.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the address of the DNS server
    /// * `sender` - the handle being used to send data to the server
    pub fn new(name_server: SocketAddr, sender: BufStreamHandle) -> Self {
        BufDnsStreamHandle {
            name_server: name_server,
            sender: sender,
        }
    }
}

impl DnsStreamHandle for BufDnsStreamHandle {
    fn send(&mut self, buffer: SerialMessage) -> Result<(), ProtoError> {
        let name_server: SocketAddr = self.name_server;
        let sender: &mut _ = &mut self.sender;
        sender
            .sender
            .unbounded_send(SerialMessage::new(buffer.unwrap().0, name_server))
            .map_err(|e| ProtoError::from(format!("mpsc::SendError {}", e)))
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
///
/// The underlying Stream implementation should yield `Some(())` whenever it is ready to send a message,
///   NotReady, if it is not ready to send a message, and `Err` or `None` in the case that the stream is
///   done, and should be shutdown.
pub trait SerialMessageSender: Stream<Item = (), Error = ProtoError> + Display + Send {
    /// A future that resolves to a response serial message
    type SerialResponse: Future<Item = DnsResponse, Error = ProtoError> + Send;

    /// Send a message, and return a future of the response
    ///
    /// # Return
    ///
    /// A future which will resolve to a SerialMessage response
    fn send_message(&mut self, message: SerialMessage) -> Self::SerialResponse;

    /// Allows the upstream user to inform the underling stream that it should shutdown.
    ///
    /// After this is called, the next time `poll` is called on the stream it would be correct to return `Ok(Async::Ready(()))`. This is not required though, if there are say outstanding requests that are not yet comlete, then it would be correct to first wait for those results.
    fn shutdown(&mut self);

    /// Returns true if the stream has been shutdown with `shutdown`
    fn is_shutdown(&self) -> bool;
}

/// Used for assiacting a name_server to a SerialMessageStreamHandle
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
    /// Construct a new BufSerialMessageStreamHandle
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

macro_rules! try_oneshot {
    ($expr:expr) => {{
        use std::result::Result;

        match $expr {
            Result::Ok(val) => val,
            Result::Err(err) => return OneshotDnsResponseReceiver::Err(Some(ProtoError::from(err))),
        }
    }};
    ($expr:expr,) => {
        $expr?
    };
}

impl<F> DnsHandle for BufSerialMessageStreamHandle<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send + 'static,
{
    type Response = OneshotDnsResponseReceiver<F>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let name_server: SocketAddr = self.name_server;
        let request: DnsRequest = request.into();
        let bytes: Vec<u8> = try_oneshot!(request.to_vec());
        let serial_message = SerialMessage::new(bytes, name_server);
        let (serial_request, oneshot) = OneshotSerialRequest::oneshot(serial_message);

        debug!("enqueueing message: {:?}", request.queries());
        try_oneshot!(
            self.sender.unbounded_send(serial_request).map_err(|_| {
                ProtoError::from(format!("could not send requesst: {}", request.id()))
            })
        );

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

    fn unwrap(self) -> (SerialMessage, OneshotDnsResponse<F>) {
        (
            self.serial_request,
            OneshotDnsResponse(self.sender_for_response),
        )
    }
}

struct OneshotDnsResponse<F>(oneshot::Sender<F>)
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send;

impl<F> OneshotDnsResponse<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    fn send_response(self, serial_response: F) -> Result<(), F> {
        self.0.send(serial_response)
    }
}

/// A Future that wraps a oneshot::Receiver and resolves to the final value
pub enum OneshotDnsResponseReceiver<F>
where
    F: Future<Item = DnsResponse, Error = ProtoError> + Send,
{
    /// The receiver
    Receiver(oneshot::Receiver<F>),
    /// The future once received
    Received(F),
    /// Error during the send operation
    Err(Option<ProtoError>),
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
                OneshotDnsResponseReceiver::Err(err) => {
                    return Err(err
                        .take()
                        .expect("futures should not be polled after complete"))
                }
            }

            *self = OneshotDnsResponseReceiver::Received(future);
        }
    }
}
