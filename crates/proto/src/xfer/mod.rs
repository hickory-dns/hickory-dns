//! DNS high level transit implimentations.
//!
//! Primarily there are two types in this module of interest, the `DnsMultiplexer` type and the `DnsHandle` type. `DnsMultiplexer` can be thought of as the state machine responsible for sending and receiving DNS messages. `DnsHandle` is the type given to API users of the `trust-dns-proto` library to send messages into the `DnsMultiplexer` for delivery. Finally there is the `DnsRequest` type. This allows for customizations, through `DnsRequestOptions`, to the delivery of messages via a `DnsMultiplexer`.
//!
//! TODO: this module needs some serious refactoring and normalization.

use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::mpsc;
use futures_channel::oneshot;
use futures_util::future::Future;
use futures_util::ready;
use futures_util::stream::{Fuse, Peekable, Stream, StreamExt};
use tracing::{debug, warn};

use crate::error::*;
use crate::Time;

mod dns_exchange;
pub mod dns_handle;
pub mod dns_multiplexer;
pub mod dns_request;
pub mod dns_response;
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub mod dnssec_dns_handle;
pub mod retry_dns_handle;
mod serial_message;

pub use self::dns_exchange::{
    DnsExchange, DnsExchangeBackground, DnsExchangeConnect, DnsExchangeSend,
};
pub use self::dns_handle::{DnsHandle, DnsStreamHandle};
pub use self::dns_multiplexer::{DnsMultiplexer, DnsMultiplexerConnect};
pub use self::dns_request::{DnsRequest, DnsRequestOptions};
pub use self::dns_response::{DnsResponse, DnsResponseStream};
#[cfg(feature = "dnssec")]
#[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
pub use self::dnssec_dns_handle::DnssecDnsHandle;
pub use self::retry_dns_handle::RetryDnsHandle;
pub use self::serial_message::SerialMessage;

/// Ignores the result of a send operation and logs and ignores errors
fn ignore_send<M, T>(result: Result<M, mpsc::TrySendError<T>>) {
    if let Err(error) = result {
        if error.is_disconnected() {
            debug!("ignoring send error on disconnected stream");
            return;
        }

        warn!("error notifying wait, possible future leak: {:?}", error);
    }
}

/// A non-multiplexed stream of Serialized DNS messages
pub trait DnsClientStream:
    Stream<Item = Result<SerialMessage, ProtoError>> + Display + Send
{
    /// Time implementation for this impl
    type Time: Time;

    /// The remote name server address
    fn name_server_addr(&self) -> SocketAddr;
}

/// Receiver handle for peekable fused SerialMessage channel
pub type StreamReceiver = Peekable<Fuse<mpsc::Receiver<SerialMessage>>>;

const CHANNEL_BUFFER_SIZE: usize = 32;

/// A buffering stream bound to a `SocketAddr`
///
/// This stream handle ensures that all messages sent via this handle have the remote_addr set as the destination for the packet
#[derive(Clone)]
pub struct BufDnsStreamHandle {
    remote_addr: SocketAddr,
    sender: mpsc::Sender<SerialMessage>,
}

impl BufDnsStreamHandle {
    /// Constructs a new Buffered Stream Handle, used for sending data to the DNS peer.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - the address of the remote DNS system (client or server)
    /// * `sender` - the handle being used to send data to the server
    pub fn new(remote_addr: SocketAddr) -> (Self, StreamReceiver) {
        let (sender, receiver) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let receiver = receiver.fuse().peekable();

        let this = Self {
            remote_addr,
            sender,
        };

        (this, receiver)
    }

    /// Associates a different remote address for any responses.
    ///
    /// This is mainly useful in server use cases where the incoming address is only known after receiving a packet.
    pub fn with_remote_addr(&self, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            sender: self.sender.clone(),
        }
    }
}

impl DnsStreamHandle for BufDnsStreamHandle {
    fn send(&mut self, buffer: SerialMessage) -> Result<(), ProtoError> {
        let remote_addr: SocketAddr = self.remote_addr;
        let sender: &mut _ = &mut self.sender;
        sender
            .try_send(SerialMessage::new(buffer.into_parts().0, remote_addr))
            .map_err(|e| ProtoError::from(format!("mpsc::SendError {}", e)))
    }
}

/// Types that implement this are capable of sending a serialized DNS message on a stream
///
/// The underlying Stream implementation should yield `Some(())` whenever it is ready to send a message,
///   NotReady, if it is not ready to send a message, and `Err` or `None` in the case that the stream is
///   done, and should be shutdown.
pub trait DnsRequestSender: Stream<Item = Result<(), ProtoError>> + Send + Unpin + 'static {
    /// Send a message, and return a stream of response
    ///
    /// # Return
    ///
    /// A stream which will resolve to SerialMessage responses
    fn send_message(&mut self, message: DnsRequest) -> DnsResponseStream;

    /// Allows the upstream user to inform the underling stream that it should shutdown.
    ///
    /// After this is called, the next time `poll` is called on the stream it would be correct to return `Poll::Ready(Ok(()))`. This is not required though, if there are say outstanding requests that are not yet complete, then it would be correct to first wait for those results.
    fn shutdown(&mut self);

    /// Returns true if the stream has been shutdown with `shutdown`
    fn is_shutdown(&self) -> bool;
}

/// Used for associating a name_server to a DnsRequestStreamHandle
#[derive(Clone)]
pub struct BufDnsRequestStreamHandle {
    sender: mpsc::Sender<OneshotDnsRequest>,
}

macro_rules! try_oneshot {
    ($expr:expr) => {{
        use std::result::Result;

        match $expr {
            Result::Ok(val) => val,
            Result::Err(err) => return DnsResponseReceiver::Err(Some(ProtoError::from(err))),
        }
    }};
    ($expr:expr,) => {
        $expr?
    };
}

impl DnsHandle for BufDnsRequestStreamHandle {
    type Response = DnsResponseReceiver;
    type Error = ProtoError;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response {
        let request: DnsRequest = request.into();
        debug!(
            "enqueueing message:{}:{:?}",
            request.op_code(),
            request.queries()
        );

        let (request, oneshot) = OneshotDnsRequest::oneshot(request);
        try_oneshot!(self.sender.try_send(request).map_err(|_| {
            debug!("unable to enqueue message");
            ProtoError::from(ProtoErrorKind::Busy)
        }));

        DnsResponseReceiver::Receiver(oneshot)
    }
}

// TODO: this future should return the origin message in the response on errors
/// A OneshotDnsRequest creates a channel for a response to message
pub struct OneshotDnsRequest {
    dns_request: DnsRequest,
    sender_for_response: oneshot::Sender<DnsResponseStream>,
}

impl OneshotDnsRequest {
    fn oneshot(dns_request: DnsRequest) -> (Self, oneshot::Receiver<DnsResponseStream>) {
        let (sender_for_response, receiver) = oneshot::channel();

        (
            Self {
                dns_request,
                sender_for_response,
            },
            receiver,
        )
    }

    fn into_parts(self) -> (DnsRequest, OneshotDnsResponse) {
        (
            self.dns_request,
            OneshotDnsResponse(self.sender_for_response),
        )
    }
}

struct OneshotDnsResponse(oneshot::Sender<DnsResponseStream>);

impl OneshotDnsResponse {
    fn send_response(self, serial_response: DnsResponseStream) -> Result<(), DnsResponseStream> {
        self.0.send(serial_response)
    }
}

/// A Stream that wraps a oneshot::Receiver<Stream> and resolves to items in the inner Stream
pub enum DnsResponseReceiver {
    /// The receiver
    Receiver(oneshot::Receiver<DnsResponseStream>),
    /// The stream once received
    Received(DnsResponseStream),
    /// Error during the send operation
    Err(Option<ProtoError>),
}

impl Stream for DnsResponseReceiver {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            *self = match *self.as_mut() {
                Self::Receiver(ref mut receiver) => {
                    let receiver = Pin::new(receiver);
                    let future = ready!(receiver
                        .poll(cx)
                        .map_err(|_| ProtoError::from("receiver was canceled")))?;
                    Self::Received(future)
                }
                Self::Received(ref mut stream) => {
                    return stream.poll_next_unpin(cx);
                }
                Self::Err(ref mut err) => return Poll::Ready(err.take().map(Err)),
            };
        }
    }
}

/// Helper trait to convert a Stream of dns response into a Future
pub trait FirstAnswer<T, E: From<ProtoError>>: Stream<Item = Result<T, E>> + Unpin + Sized {
    /// Convert a Stream of dns response into a Future yielding the first answer,
    /// discarding others if any.
    fn first_answer(self) -> FirstAnswerFuture<Self> {
        FirstAnswerFuture { stream: Some(self) }
    }
}

impl<E, S, T> FirstAnswer<T, E> for S
where
    S: Stream<Item = Result<T, E>> + Unpin + Sized,
    E: From<ProtoError>,
{
}

/// See [FirstAnswer::first_answer]
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct FirstAnswerFuture<S> {
    stream: Option<S>,
}

impl<E, S: Stream<Item = Result<T, E>> + Unpin, T> Future for FirstAnswerFuture<S>
where
    S: Stream<Item = Result<T, E>> + Unpin + Sized,
    E: From<ProtoError>,
{
    type Output = S::Item;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self
            .stream
            .as_mut()
            .expect("polling FirstAnswerFuture twice");
        let item = match ready!(s.poll_next_unpin(cx)) {
            Some(r) => r,
            None => Err(ProtoError::from(ProtoErrorKind::Timeout).into()),
        };
        self.stream.take();
        Poll::Ready(item)
    }
}
