// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsHandle` types perform conversions of the raw DNS messages before sending the messages on the specified streams.

use futures::future::{Future, FutureExt, TryFutureExt};
use futures::channel::mpsc::UnboundedSender;
use futures::channel::oneshot;
use rand;

use crate::error::*;
use crate::op::{Message, MessageType, OpCode, Query};
use crate::xfer::{ignore_send, DnsRequest, DnsRequestOptions, DnsResponse, SerialMessage};

// TODO: this should be configurable
const MAX_PAYLOAD_LEN: u16 = 1500 - 40 - 8; // 1500 (general MTU) - 40 (ipv6 header) - 8 (udp header)

/// The StreamHandle is the general interface for communicating with the DnsMultiplexer
pub struct StreamHandle {
    sender: UnboundedSender<Vec<u8>>,
}

impl StreamHandle {
    /// Constructs a new StreamHandle for wrapping the sender
    pub fn new(sender: UnboundedSender<Vec<u8>>) -> Self {
        StreamHandle { sender }
    }
}

/// Implementations of Sinks for sending DNS messages
pub trait DnsStreamHandle: 'static + Send {
    /// Sends a message to the Handle for delivery to the server.
    fn send(&mut self, buffer: SerialMessage) -> Result<(), ProtoError>;
}

impl DnsStreamHandle for StreamHandle {
    fn send(&mut self, buffer: SerialMessage) -> Result<(), ProtoError> {
        UnboundedSender::unbounded_send(&self.sender, buffer.unwrap().0)
            .map_err(|e| ProtoError::from(format!("mpsc::SendError {}", e)))
    }
}

/// Root DnsHandle implementation returned by DnsMultiplexer
///
/// This can be used directly to perform queries. See `trust_dns::client::SecureDnsHandle` for
///  a DNSSEc chain validator.
#[derive(Clone)]
pub struct BasicDnsHandle {
    message_sender: UnboundedSender<(DnsRequest, oneshot::Sender<Result<DnsResponse, ProtoError>>)>,
}

impl BasicDnsHandle {
    /// Returns a new BasicDnsHandle wrapping the `message_sender`
    pub fn new(
        message_sender: UnboundedSender<(
            DnsRequest,
            oneshot::Sender<Result<DnsResponse, ProtoError>>,
        )>,
    ) -> Self {
        BasicDnsHandle { message_sender }
    }
}

impl DnsHandle for BasicDnsHandle {
    type Response = Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send + Unpin>;

    fn send<R: Into<DnsRequest>>(
        &mut self,
        request: R,
    ) -> Self::Response {
        let request = request.into();
        let (complete, receiver) = oneshot::channel();
        let message_sender: &mut _ = &mut self.message_sender;

        // TODO: update to use Sink::send
        let receiver = match UnboundedSender::unbounded_send(message_sender, (request, complete)) {
            Ok(()) => receiver,
            Err(e) => {
                let (complete, receiver) = oneshot::channel();
                ignore_send(complete.send(Err(ProtoError::from(format!(
                    "error sending to channel: {}",
                    e
                )))));
                receiver
            }
        };

        // convert the oneshot into a Box of a Future message and error.
        Box::new(
            receiver
                .map_err(|c| ProtoError::from(ProtoErrorKind::Canceled(c)))
                .map(|r| r.and_then(|r| r)),
        )
    }
}

/// A trait for implementing high level functions of DNS.
pub trait DnsHandle: 'static + Clone + Send {
    /// The associated response from the response future, this should resolve to the Response message
    type Response: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin;

    /// Only returns true if and only if this DNS handle is validating DNSSec.
    ///
    /// If the DnsHandle impl is wrapping other clients, then the correct option is to delegate the question to the wrapped client.
    fn is_verifying_dnssec(&self) -> bool {
        false
    }

    /// Send a message via the channel in the client
    ///
    /// # Arguments
    ///
    /// * `request` - the fully constructed Message to send, note that most implementations of
    ///               will most likely be required to rewrite the QueryId, do no rely on that as
    ///               being stable.
    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> Self::Response;

    /// A *classic* DNS query
    ///
    /// This is identical to `query`, but instead takes a `Query` object.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to lookup
    fn lookup(&mut self, query: Query, options: DnsRequestOptions) -> Self::Response {
        debug!("querying: {} {:?}", query.name(), query.query_type());

        // build the message
        let mut message: Message = Message::new();

        // TODO: This is not the final ID, it's actually set in the poll method of DNS future
        //  should we just remove this?
        let id: u16 = rand::random();

        message.add_query(query);
        message
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);

        // Extended dns
        {
            // TODO: this should really be configurable...
            let edns = message.edns_mut();
            edns.set_max_payload(MAX_PAYLOAD_LEN);
            edns.set_version(0);
        }

        self.send(DnsRequest::new(message, options))
    }
}
