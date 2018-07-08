//! DNS high level transit implimentations.
//!
//! Primarily there are two types in this module of interest, the `DnsFuture` type and the `DnsHandle` type. `DnsFuture` can be thought of as the state machine responsible for sending and receiving DNS messages. `DnsHandle` is the type given to API users of the `trust-dns-proto` library to send messages into the `DnsFuture` for delivery. Finally there is the `DnsRequest` type. This allows for customizations, through `DnsReqeustOptions`, to the delivery of messages via a `DnsFuture`.

use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;

use error::*;
use futures::sync::mpsc::{SendError, UnboundedSender};
use futures::Future;
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
#[derive(Clone)]
pub struct SerialMessageStreamHandle<E>
where
    E: FromProtoError,
{
    sender: UnboundedSender<SerialMessage>,
    phantom: PhantomData<E>,
}

impl<E> SerialMessageStreamHandle<E>
where
    E: FromProtoError,
{
    /// Constructs a new BufStreamHandle with the associated ProtoError
    pub fn new(sender: UnboundedSender<SerialMessage>) -> Self {
        SerialMessageStreamHandle {
            sender,
            phantom: PhantomData::<E>,
        }
    }

    /// see [`futures::sync::mpsc::UnboundedSender`]
    pub fn unbounded_send(&self, msg: SerialMessage) -> Result<(), SendError<SerialMessage>> {
        self.sender.unbounded_send(msg)
    }
}

// FIXME: change io::Error to FromProtoError
/// Types that implement this are capable of sending a serialized DNS message on a stream
pub trait SerialMessageSender {
    /// A future that resolves to a response serial message
    type SerialResponse: Future<Item = SerialMessage, Error = io::Error>;

    /// Send a message, and return a future of the response
    ///
    /// # Return
    ///
    /// A future which will resolve to a SerialMessage response
    fn send_message(&mut self, message: SerialMessage) -> Self::SerialResponse;
}

// /// A result of SerialMessageSender::send_message
// pub enum SendMessageAsync<F>
// where
//     F: Future<Item = SerialMessage, Error = io::Error>,
// {
//     /// The message can not be sent, try again
//     NotReady(SerialMessage),
//     /// The message send was initiated, returning the future result
//     Ready(F),
// }

// /// The result of a SerialMessageSender::send_message
// pub type SendMessage<F, E> = Result<SendMessageAsync<F>, E>;

// pub struct BoundSerialMessageSender<S, R>
// where
//     S: SerialMessageSender<SerialResponse = R>,
//     R: Future<Item = SerialMessage, Error = io::Error>,
// {
//     name_server: SocketAddr,
//     sender: S,
// }

// impl<S, R, E> DnsStreamHandle
// where
//     S: SerialMessageSender<SerialResponse = R>,
//     R: Future<Item = SerialMessage, Error = io::Error>,
//     E: FromProtoError,
// {
//     type Error = E;

//     fn send(&mut self, buffer: Vec<u8>) -> Result<(), E> {
//         let name_server: SocketAddr = self.name_server;
//         let sender: &mut _ = &mut self.sender;
//         sender
//             .sender
//             .unbounded_send(SerialMessage::new(buffer, name_server))
//             .map_err(|e| E::from(format!("mpsc::SendError {}", e).into()))
//     }
// }
