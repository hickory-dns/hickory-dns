//! DNS high level transit implimentations.
//!
//! Primarily there are two types in this module of interest, the `DnsMultiplexer` type and the `DnsHandle` type. `DnsMultiplexer` can be thought of as the state machine responsible for sending and receiving DNS messages. `DnsHandle` is the type given to API users of the `trust-dns-proto` library to send messages into the `DnsMultiplexer` for delivery. Finally there is the `DnsRequest` type. This allows for customizations, through `DnsRequestOptions`, to the delivery of messages via a `DnsMultiplexer`.
//!
//! TODO: this module needs some serious refactoring and normalization.

use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::mpsc::{TrySendError, UnboundedSender};
use futures::channel::oneshot::{self, Receiver, Sender};
use futures::{ready, Future, Stream};
use log::{debug, warn};

use crate::error::*;
use crate::Time;

mod dns_exchange;
pub mod dns_handle;
pub mod dns_multiplexer;
pub mod dns_request;
pub mod dns_response;
#[cfg(feature = "dnssec")]
pub mod dnssec_dns_handle;
pub mod retry_dns_handle;
mod serial_message;

pub use self::dns_exchange::{
    DnsExchange, DnsExchangeBackground, DnsExchangeConnect, DnsExchangeSend,
};
pub use self::dns_handle::{DnsHandle, DnsStreamHandle, StreamHandle};
pub use self::dns_multiplexer::{
    DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse,
};
pub use self::dns_request::{DnsRequest, DnsRequestOptions};
pub use self::dns_response::DnsResponse;
#[cfg(feature = "dnssec")]
pub use self::dnssec_dns_handle::DnssecDnsHandle;
pub use self::retry_dns_handle::RetryDnsHandle;
pub use self::serial_message::SerialMessage;

/// Ignores the result of a send operation and logs and ignores errors
fn ignore_send<M, E: Debug>(result: Result<M, E>) {
    if let Err(error) = result {
        warn!("error notifying wait, possible future leak: {:?}", error);
    }
}

/// A non-multiplexed stream of Serialized DNS messages
pub trait DnsClientStream:
    Stream<Item = Result<SerialMessage, ProtoError>> + Display + Send
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
    pub fn unbounded_send(&self, msg: SerialMessage) -> Result<(), TrySendError<SerialMessage>> {
        self.sender.unbounded_send(msg)
    }
}

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
            name_server,
            sender,
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
pub struct DnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    sender: UnboundedSender<OneshotDnsRequest<F>>,
}

impl<F> DnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    /// Constructs a new BufStreamHandle with the associated ProtoError
    pub fn new(sender: UnboundedSender<OneshotDnsRequest<F>>) -> Self {
        DnsRequestStreamHandle { sender }
    }

    /// see [`futures::sync::mpsc::UnboundedSender`]
    pub fn unbounded_send(
        &self,
        msg: OneshotDnsRequest<F>,
    ) -> Result<(), TrySendError<OneshotDnsRequest<F>>> {
        self.sender.unbounded_send(msg)
    }
}

impl<F> Clone for DnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    fn clone(&self) -> Self {
        DnsRequestStreamHandle {
            sender: self.sender.clone(),
        }
    }
}

/// Types that implement this are capable of sending a serialized DNS message on a stream
///
/// The underlying Stream implementation should yield `Some(())` whenever it is ready to send a message,
///   NotReady, if it is not ready to send a message, and `Err` or `None` in the case that the stream is
///   done, and should be shutdown.
pub trait DnsRequestSender: Stream<Item = Result<(), ProtoError>> + Send + Unpin + 'static {
    /// A future that resolves to a response serial message
    type DnsResponseFuture: Future<Output = Result<DnsResponse, ProtoError>>
        + 'static
        + Send
        + Unpin;

    /// Send a message, and return a future of the response
    ///
    /// # Return
    ///
    /// A future which will resolve to a SerialMessage response
    fn send_message<TE: Time>(
        &mut self,
        message: DnsRequest,
        cx: &mut Context,
    ) -> Self::DnsResponseFuture;

    /// Constructs an error response
    fn error_response<TE: Time>(error: ProtoError) -> Self::DnsResponseFuture;

    /// Allows the upstream user to inform the underling stream that it should shutdown.
    ///
    /// After this is called, the next time `poll` is called on the stream it would be correct to return `Poll::Ready(Ok(()))`. This is not required though, if there are say outstanding requests that are not yet complete, then it would be correct to first wait for those results.
    fn shutdown(&mut self);

    /// Returns true if the stream has been shutdown with `shutdown`
    fn is_shutdown(&self) -> bool;
}

/// Used for associating a name_server to a DnsRequestStreamHandle
pub struct BufDnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    sender: DnsRequestStreamHandle<F>,
}

impl<F> BufDnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    /// Construct a new BufDnsRequestStreamHandle
    pub fn new(sender: DnsRequestStreamHandle<F>) -> Self {
        BufDnsRequestStreamHandle { sender }
    }
}

impl<F> Clone for BufDnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    fn clone(&self) -> Self {
        BufDnsRequestStreamHandle {
            sender: self.sender.clone(),
        }
    }
}

macro_rules! try_oneshot {
    ($expr:expr) => {{
        use std::result::Result;

        match $expr {
            Result::Ok(val) => val,
            Result::Err(err) => {
                return OneshotDnsResponseReceiver::Err(Some(ProtoError::from(err)))
            }
        }
    }};
    ($expr:expr,) => {
        $expr?
    };
}

impl<F> DnsHandle for BufDnsRequestStreamHandle<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    type Response = OneshotDnsResponseReceiver<F>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request: DnsRequest = request.into();
        debug!("enqueueing message: {:?}", request.queries());

        let (request, oneshot) = OneshotDnsRequest::oneshot(request);
        try_oneshot!(self.sender.unbounded_send(request).map_err(|_| {
            debug!("unable to enqueue message");
            ProtoError::from("could not send request")
        }));

        OneshotDnsResponseReceiver::Receiver(oneshot)
    }
}

// TODO: this future should return the origin message in the response on errors
/// A OneshotDnsRequest creates a channel for a response to message
pub struct OneshotDnsRequest<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    dns_request: DnsRequest,
    sender_for_response: Sender<F>,
}

impl<F> OneshotDnsRequest<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    fn oneshot(dns_request: DnsRequest) -> (OneshotDnsRequest<F>, oneshot::Receiver<F>) {
        let (sender_for_response, receiver) = oneshot::channel();

        (
            OneshotDnsRequest {
                dns_request,
                sender_for_response,
            },
            receiver,
        )
    }

    fn unwrap(self) -> (DnsRequest, OneshotDnsResponse<F>) {
        (
            self.dns_request,
            OneshotDnsResponse(self.sender_for_response),
        )
    }
}

struct OneshotDnsResponse<F>(oneshot::Sender<F>)
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send;

impl<F> OneshotDnsResponse<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send,
{
    fn send_response(self, serial_response: F) -> Result<(), F> {
        self.0.send(serial_response)
    }
}

/// A Future that wraps a oneshot::Receiver and resolves to the final value
pub enum OneshotDnsResponseReceiver<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
    /// The receiver
    Receiver(Receiver<F>),
    /// The future once received
    Received(F),
    /// Error during the send operation
    Err(Option<ProtoError>),
}

impl<F> Future for OneshotDnsResponseReceiver<F>
where
    F: Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin,
{
    type Output = <F as Future>::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            *self = match *self.as_mut() {
                OneshotDnsResponseReceiver::Receiver(ref mut receiver) => {
                    let receiver = Pin::new(receiver);
                    let future = ready!(receiver
                        .poll(cx)
                        .map_err(|_| ProtoError::from("receiver was canceled")))?;
                    OneshotDnsResponseReceiver::Received(future)
                }
                OneshotDnsResponseReceiver::Received(ref mut future) => {
                    let future = Pin::new(future);
                    return future.poll(cx);
                }
                OneshotDnsResponseReceiver::Err(ref mut err) => {
                    return Poll::Ready(Err(err
                        .take()
                        .expect("futures should not be polled after complete")))
                }
            };
        }
    }
}
