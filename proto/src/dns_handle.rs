// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::borrow::Borrow;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::io;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


use futures::{task, Async, Complete, Future, Poll};
use futures::IntoFuture;
use futures::stream::{Fuse as StreamFuse, Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use rand;
use rand::distributions::{IndependentSample, Range};
use tokio_core::reactor::{Handle, Timeout};

use error::*;
use op::{Message, MessageFinalizer, MessageType, OpCode, Query};

// TODO: this should be configurable
const MAX_PAYLOAD_LEN: u16 = 1500 - 40 - 8; // 1500 (general MTU) - 40 (ipv6 header) - 8 (udp header)
const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

/// The StreamHandle is the general interface for communicating with the DnsFuture
pub struct StreamHandle<E>
where
    E: FromProtoError,
{
    sender: UnboundedSender<Vec<u8>>,
    phantom: PhantomData<E>,
}

impl<E> StreamHandle<E>
where
    E: FromProtoError,
{
    /// Constructs a new StreamHandle for wrapping the sender
    pub fn new(sender: UnboundedSender<Vec<u8>>) -> Self {
        StreamHandle {
            sender,
            phantom: PhantomData::<E>,
        }
    }
}

/// Implementations of Sinks for sending DNS messages
pub trait DnsStreamHandle {
    /// The Error type to be returned if there is an error
    type Error: FromProtoError;

    /// Sends a message to the Handle for delivery to the server.
    fn send(&mut self, buffer: Vec<u8>) -> Result<(), Self::Error>;
}

impl<E> DnsStreamHandle for StreamHandle<E>
where
    E: FromProtoError,
{
    type Error = E;

    fn send(&mut self, buffer: Vec<u8>) -> Result<(), Self::Error> {
        UnboundedSender::unbounded_send(&self.sender, buffer).map_err(|e| {
            E::from(ProtoErrorKind::Msg(format!("mpsc::SendError {}", e)).into())
        })
    }
}

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
#[must_use = "futures do nothing unless polled"]
pub struct DnsFuture<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error>,
    E: FromProtoError,
    MF: MessageFinalizer,
{
    stream: S,
    reactor_handle: Handle,
    timeout_duration: Duration,
    // TODO: genericize and remove this Box
    stream_handle: Box<DnsStreamHandle<Error = E>>,
    new_receiver: Peekable<StreamFuse<UnboundedReceiver<(Message, Complete<Result<Message, E>>)>>>,
    active_requests: HashMap<u16, (Complete<Result<Message, E>>, Timeout)>,
    signer: Option<Arc<MF>>,
}

impl<S, E, MF> DnsFuture<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    E: FromProtoError + 'static,
    MF: MessageFinalizer + 'static,
{
    /// Spawns a new DnsFuture Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `loop_handle` - A Handle to the Tokio reactor Core, this is the Core on which the
    ///                   the Stream will be spawned
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn new(
        stream: Box<Future<Item = S, Error = io::Error>>,
        stream_handle: Box<DnsStreamHandle<Error = E>>,
        loop_handle: &Handle,
        signer: Option<Arc<MF>>,
    ) -> BasicDnsHandle<E> {
        Self::with_timeout(
            stream,
            stream_handle,
            loop_handle,
            Duration::from_secs(5),
            signer,
        )
    }

    /// Spawns a new DnsFuture Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `loop_handle` - A Handle to the Tokio reactor Core, this is the Core on which the
    ///                   the Stream will be spawned
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///                        wait for a response before canceling the request.
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn with_timeout(
        stream: Box<Future<Item = S, Error = io::Error>>,
        stream_handle: Box<DnsStreamHandle<Error = E>>,
        loop_handle: &Handle,
        timeout_duration: Duration,
        signer: Option<Arc<MF>>,
    ) -> BasicDnsHandle<E> {
        let (sender, rx) = unbounded();

        let loop_handle_clone = loop_handle.clone();
        loop_handle.spawn(
            stream
                .then(move |res| match res {
                    Ok(stream) => ClientStreamOrError::Future(DnsFuture {
                        stream: stream,
                        reactor_handle: loop_handle_clone,
                        timeout_duration: timeout_duration,
                        stream_handle: stream_handle,
                        new_receiver: rx.fuse().peekable(),
                        active_requests: HashMap::new(),
                        signer: signer,
                    }),
                    Err(stream_error) => ClientStreamOrError::Errored(ClientStreamErrored {
                        error_msg: format!(
                            "stream error {}:{}: {}",
                            file!(),
                            line!(),
                            stream_error
                        ),
                        new_receiver: rx.fuse().peekable(),
                    }),
                })
                .map_err(|e| {
                    error!("error in Proto: {}", e);
                }),
        );

        BasicDnsHandle {
            message_sender: sender,
        }
    }

    /// loop over active_requests and remove cancelled requests
    ///  this should free up space if we already had 4096 active requests
    fn drop_cancelled(&mut self) {
        // TODO: should we have a timeout here? or always expect the caller to do this?
        let mut canceled = HashSet::new();
        for (&id, &mut (ref mut req, ref mut timeout)) in &mut self.active_requests {
            if let Ok(Async::Ready(())) = req.poll_cancel() {
                canceled.insert(id);
            }

            // check for timeouts...
            match timeout.poll() {
                Ok(Async::Ready(_)) => {
                    warn!("request timeout: {}", id);
                    canceled.insert(id);
                }
                Ok(Async::NotReady) => (),
                Err(e) => {
                    error!("unexpected error from timeout: {}", e);
                    canceled.insert(id);
                }
            }
        }

        // drop all the canceled requests
        for id in canceled {
            if let Some((req, _)) = self.active_requests.remove(&id) {
                // TODO, perhaps there is a different reason timeout? but there shouldn't be...
                //  being lazy and always returning timeout in this case (if it was canceled then the
                //  then the otherside isn't really paying attention anyway)

                // complete the request, it's failed...
                req.send(Err(E::from(ProtoErrorKind::Timeout.into())))
                    .expect("error notifying wait, possible future leak");
            }
        }
    }

    /// creates random query_id, validates against all active queries
    fn next_random_query_id(&self) -> Async<u16> {
        let between = Range::new(0_u32, u32::from(u16::max_value()) + 1);
        let mut rand = rand::thread_rng();

        for _ in 0..100 {
            let id = between.ind_sample(&mut rand) as u16; // the range is [0 ... u16::max] aka [0 .. u16::max + 1)

            if !self.active_requests.contains_key(&id) {
                return Async::Ready(id);
            }
        }

        warn!("could not get next random query id, delaying");
        task::current().notify();
        Async::NotReady
    }
}

impl<S, E, MF> Future for DnsFuture<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    E: FromProtoError + 'static,
    MF: MessageFinalizer + 'static,
{
    type Item = ();
    type Error = E;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        self.drop_cancelled();

        // loop over new_receiver for all outbound requests
        loop {
            // get next query_id
            let query_id: Option<u16> = match self.new_receiver.peek() {
                Ok(Async::Ready(Some(_))) => {
                    debug!("got message from receiver");

                    // we have a new message to send
                    match self.next_random_query_id() {
                        Async::Ready(id) => Some(id),
                        Async::NotReady => break,
                    }
                }
                Ok(_) => None,
                Err(()) => {
                    warn!("receiver was shutdown?");
                    break;
                }
            };

            // finally pop the reciever
            match self.new_receiver.poll() {
                Ok(Async::Ready(Some((mut message, complete)))) => {
                    // if there was a message, and the above succesion was succesful,
                    //  register the new message, if not do not register, and set the complete to error.
                    // getting a random query id, this mitigates potential cache poisoning.
                    let query_id = query_id.expect("query_id should have been set above");
                    message.set_id(query_id);

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "Current time is before the Unix epoch.".into())?
                        .as_secs();
                    let now = now as u32; // XXX: truncates u64 to u32.

                    // update messages need to be signed.
                    if let OpCode::Update = message.op_code() {
                        if let Some(ref signer) = self.signer {
                            if let Err(e) = message.finalize::<MF>(signer.borrow(), now) {
                                warn!("could not sign message: {}", e);
                                complete
                                    .send(Err(e.into()))
                                    .expect("error notifying wait, possible future leak");
                                continue; // to the next message...
                            }
                        }
                    }

                    // store a Timeout for this message before sending
                    let timeout = match Timeout::new(self.timeout_duration, &self.reactor_handle) {
                        Ok(timeout) => timeout,
                        Err(e) => {
                            warn!("could not create timer: {}", e);
                            complete
                                .send(Err(E::from(e.into())))
                                .expect("error notifying wait, possible future leak");
                            continue; // to the next message...
                        }
                    };

                    // send the message
                    match message.to_vec() {
                        Ok(buffer) => {
                            debug!("sending message id: {}", query_id);
                            self.stream_handle.send(buffer)?;
                            // add to the map -after- the client send b/c we don't want to put it in the map if
                            //  we ended up returning from the send.
                            self.active_requests
                                .insert(message.id(), (complete, timeout));
                        }
                        Err(e) => {
                            debug!("error message id: {} error: {}", query_id, e);
                            // complete with the error, don't add to the map of active requests
                            complete
                                .send(Err(e.into()))
                                .expect("error notifying wait, possible future leak");
                        }
                    }
                }
                Ok(_) => break,
                Err(()) => {
                    warn!("receiver was shutdown?");
                    break;
                }
            }
        }

        // Collect all inbound requests, max 100 at a time for QoS
        //   by having a max we will guarantee that the client can't be DOSed in this loop
        // TODO: make the QoS configurable
        let mut messages_received = 0;
        for i in 0..QOS_MAX_RECEIVE_MSGS {
            match self.stream.poll().map_err(|e| E::from(e.into()))? {
                Async::Ready(Some(buffer)) => {
                    messages_received = i;

                    //   deserialize or log decode_error
                    match Message::from_vec(&buffer) {
                        Ok(message) => match self.active_requests.remove(&message.id()) {
                            Some((complete, _)) => complete
                                .send(Ok(message))
                                .expect("error notifying wait, possible future leak"),
                            None => debug!("unexpected request_id: {}", message.id()),
                        },
                        // TODO: return src address for diagnostics
                        Err(e) => debug!("error decoding message: {}", e),
                    }
                }
                Async::Ready(None) | Async::NotReady => break,
            }
        }

        // Clean shutdown happens when all pending requests are done and the
        // incoming channel has been closed (e.g. you'll never receive another
        // request). Errors wiil return early...
        let done = match self.new_receiver.peek() {
            Ok(Async::Ready(None)) => true,
            Ok(_) => false,
            Err(_) => return Err(E::from(ProtoErrorKind::NoError.into())),
        };

        if self.active_requests.is_empty() && done {
            return Ok(().into()); // we are done
        }

        // If still active, then if the qos (for _ in 0..100 loop) limit
        // was hit then "yield". This'll make sure that the future is
        // woken up immediately on the next turn of the event loop.
        if messages_received == QOS_MAX_RECEIVE_MSGS {
            task::current().notify();
        }

        // Finally, return not ready to keep the 'driver task' alive.
        Ok(Async::NotReady)
    }
}

/// Always returns the specified io::Error to the remote Sender
struct ClientStreamErrored<E>
where
    E: FromProtoError,
{
    // TODO: is there a better thing to grab here?
    error_msg: String,
    new_receiver: Peekable<StreamFuse<UnboundedReceiver<(Message, Complete<Result<Message, E>>)>>>,
}

impl<E> Future for ClientStreamErrored<E>
where
    E: FromProtoError,
{
    type Item = ();
    type Error = E;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        match self.new_receiver.poll() {
            Ok(Async::Ready(Some((_, complete)))) => {
                complete
                    .send(Err(
                        E::from(ProtoErrorKind::Msg(self.error_msg.clone()).into()),
                    ))
                    .expect("error notifying wait, possible future leak");

                task::current().notify();
                Ok(Async::NotReady)
            }
            Ok(Async::Ready(None)) => Ok(Async::Ready(())),
            _ => Err(E::from(ProtoErrorKind::NoError.into())),
        }
    }
}

enum ClientStreamOrError<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    E: FromProtoError,
    MF: MessageFinalizer + 'static,
{
    Future(DnsFuture<S, E, MF>),
    Errored(ClientStreamErrored<E>),
}

impl<S, E, MF> Future for ClientStreamOrError<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    E: FromProtoError + 'static,
    MF: MessageFinalizer + 'static,
{
    type Item = ();
    type Error = E;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        match *self {
            ClientStreamOrError::Future(ref mut f) => f.poll(),
            ClientStreamOrError::Errored(ref mut e) => e.poll(),
        }
    }
}

/// Root DnsHandle implementaton returned by DnsFuture
///
/// This can be used directly to perform queries. See `trust_dns::client::SecureDnsHandle` for
///  a DNSSEc chain validator.
#[derive(Clone)]
pub struct BasicDnsHandle<E: FromProtoError> {
    message_sender: UnboundedSender<(Message, Complete<Result<Message, E>>)>,
}

impl<E> DnsHandle for BasicDnsHandle<E>
where
    E: FromProtoError + 'static,
{
    type Error = E;

    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        let (complete, receiver) = oneshot::channel();
        let message_sender: &mut _ = &mut self.message_sender;

        // TODO: update to use Sink::send
        let receiver = match UnboundedSender::unbounded_send(message_sender, (message, complete)) {
            Ok(()) => receiver,
            Err(e) => {
                let (complete, receiver) = oneshot::channel();
                complete
                    .send(Err(E::from(
                        ProtoErrorKind::Msg(format!("error sending to channel: {}", e)).into(),
                    )))
                    .expect("error notifying wait, possible future leak");
                receiver
            }
        };

        // conver the oneshot into a Box of a Future message and error.
        Box::new(
            receiver
                .map_err(|c| ProtoError::from(ProtoErrorKind::Canceled(c)))
                .map(|result| result.into_future())
                .flatten(),
        )
    }
}

/// A trait for implementing high level functions of DNS.
pub trait DnsHandle: Clone {
    /// The associated error type returned by future send operations
    type Error: FromProtoError;

    /// Ony returns true if and only if this DNS handle is validating DNSSec.
    ///
    /// If the DnsHandle impl is wrapping other clients, then the correct option is to delegate the question to the wrapped client.
    fn is_verifying_dnssec(&self) -> bool {
        false
    }

    /// Send a message via the channel in the client
    ///
    /// # Arguments
    ///
    /// * `message` - the fully constructed Message to send, note that most implementations of
    ///               will most likely be required to rewrite the QueryId, do no rely on that as
    ///               being stable.
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = Self::Error>>;

    /// A *classic* DNS query
    ///
    /// This is identical to `query`, but instead takes a `Query` object.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to lookup
    fn lookup(&mut self, query: Query) -> Box<Future<Item = Message, Error = Self::Error>> {
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

        self.send(message)
    }
}
