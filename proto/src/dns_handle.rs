// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Duration;

use chrono::Utc;
use futures::{Async, Complete, Future, Poll, task};
use futures::IntoFuture;
use futures::stream::{Peekable, Fuse as StreamFuse, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::oneshot;
use rand::Rng;
use rand;
use tokio_core::reactor::{Handle, Timeout};

use error::*;
use op::{Message, MessageFinalizer, OpCode};

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

/// The StreamHandle is the general interface for communicating with the DnsFuture
pub type StreamHandle = UnboundedSender<Vec<u8>>;

/// Implementations of Sinks for sending DNS messages
pub trait DnsStreamHandle {
    /// Sends a message to the Handle for delivery to the server.
    fn send(&mut self, buffer: Vec<u8>) -> ProtoResult<()>;
}

impl DnsStreamHandle for StreamHandle {
    fn send(&mut self, buffer: Vec<u8>) -> ProtoResult<()> {
        UnboundedSender::unbounded_send(self, buffer).map_err(|e| {
            ProtoErrorKind::Msg(format!("mpsc::SendError {}", e)).into()
        })
    }
}

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations.
#[must_use = "futures do nothing unless polled"]
pub struct DnsFuture<S: Stream<Item = Vec<u8>, Error = io::Error>, MF: MessageFinalizer> {
    stream: S,
    reactor_handle: Handle,
    timeout_duration: Duration,
    // TODO: genericize and remove this Box
    stream_handle: Box<DnsStreamHandle>,
    new_receiver:
        Peekable<StreamFuse<UnboundedReceiver<(Message, Complete<ProtoResult<Message>>)>>>,
    active_requests: HashMap<u16, (Complete<ProtoResult<Message>>, Timeout)>,
    signer: Option<MF>,
}

impl<S, MF> DnsFuture<S, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
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
        stream_handle: Box<DnsStreamHandle>,
        loop_handle: &Handle,
        signer: Option<MF>,
    ) -> BasicDnsHandle {
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
        stream_handle: Box<DnsStreamHandle>,
        loop_handle: &Handle,
        timeout_duration: Duration,
        signer: Option<MF>,
    ) -> BasicDnsHandle {
        let (sender, rx) = unbounded();

        let loop_handle_clone = loop_handle.clone();
        loop_handle.spawn(
            stream
                .then(move |res| match res {
                    Ok(stream) => {
                        ClientStreamOrError::Future(DnsFuture {
                            stream: stream,
                            reactor_handle: loop_handle_clone,
                            timeout_duration: timeout_duration,
                            stream_handle: stream_handle,
                            new_receiver: rx.fuse().peekable(),
                            active_requests: HashMap::new(),
                            signer: signer,
                        })
                    }
                    Err(stream_error) => {
                        ClientStreamOrError::Errored(ClientStreamErrored {
                            error_msg: format!(
                                "stream error {}:{}: {}",
                                file!(),
                                line!(),
                                stream_error
                            ),
                            new_receiver: rx.fuse().peekable(),
                        })
                    }
                })
                .map_err(|e: ProtoError| {
                    error!("error in Client: {}", e);
                }),
        );

        BasicDnsHandle { message_sender: sender }
    }

    /// loop over active_requests and remove cancelled requests
    ///  this should free up space if we already had 4096 active requests
    fn drop_cancelled(&mut self) {
        // TODO: should we have a timeout here? or always expect the caller to do this?
        let mut canceled = HashSet::new();
        for (&id, &mut (ref mut req, ref mut timeout)) in self.active_requests.iter_mut() {
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
                req.send(Err(ProtoErrorKind::Timeout.into())).expect(
                    "error notifying wait, possible future leak",
                );
            }
        }
    }

    /// creates random query_id, validates against all active queries
    fn next_random_query_id(&self) -> Async<u16> {
        let mut rand = rand::thread_rng();

        for _ in 0..100 {
            let id = rand.gen_range(0_u16, u16::max_value());

            if !self.active_requests.contains_key(&id) {
                return Async::Ready(id);
            }
        }

        warn!("could not get next random query id, delaying");
        task::current().notify();
        Async::NotReady
    }
}

impl<S, MF> Future for DnsFuture<S, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    MF: MessageFinalizer + 'static,
{
    type Item = ();
    type Error = ProtoError;

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
                    break
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

                    // update messages need to be signed.
                    if let OpCode::Update = message.op_code() {
                        if let Some(ref signer) = self.signer {
                            if let Err(e) = message.finalize(
                                signer,
                                Utc::now().timestamp() as u32,
                            )
                            {
                                warn!("could not sign message: {}", e);
                                complete.send(Err(e.into())).expect(
                                    "error notifying wait, possible future leak",
                                );
                                continue; // to the next message...
                            }
                        }
                    }

                    // store a Timeout for this message before sending
                    let timeout = match Timeout::new(self.timeout_duration, &self.reactor_handle) {
                        Ok(timeout) => timeout,
                        Err(e) => {
                            warn!("could not create timer: {}", e);
                            complete.send(Err(e.into())).expect(
                                "error notifying wait, possible future leak",
                            );
                            continue; // to the next message...
                        }
                    };

                    // send the message
                    match message.to_vec() {
                        Ok(buffer) => {
                            debug!("sending message id: {}", query_id);
                            try!(self.stream_handle.send(buffer));
                            // add to the map -after- the client send b/c we don't want to put it in the map if
                            //  we ended up returning from the send.
                            self.active_requests.insert(
                                message.id(),
                                (complete, timeout),
                            );
                        }
                        Err(e) => {
                            debug!("error message id: {} error: {}", query_id, e);
                            // complete with the error, don't add to the map of active requests
                            complete.send(Err(e.into())).expect(
                                "error notifying wait, possible future leak",
                            );
                        }
                    }
                }
                Ok(_) => break,
                Err(()) => {
          warn!("receiver was shutdown?");
          break
        }
            }
        }

        // Collect all inbound requests, max 100 at a time for QoS
        //   by having a max we will guarantee that the client can't be DOSed in this loop
        // TODO: make the QoS configurable
        let mut messages_received = 0;
        for i in 0..QOS_MAX_RECEIVE_MSGS {
            match try!(self.stream.poll()) {
                Async::Ready(Some(buffer)) => {
                    messages_received = i;

                    //   deserialize or log decode_error
                    match Message::from_vec(&buffer) {
                        Ok(message) => {
                            match self.active_requests.remove(&message.id()) {
                                Some((complete, _)) => {
                                    complete.send(Ok(message)).expect(
                                        "error notifying wait, possible future leak",
                                    )
                                }
                                None => debug!("unexpected request_id: {}", message.id()),
                            }
                        }
                        // TODO: return src address for diagnostics
                        Err(e) => debug!("error decoding message: {}", e),
                    }

                }
                Async::Ready(None) |
                Async::NotReady => break,
            }
        }

        // Clean shutdown happens when all pending requests are done and the
        // incoming channel has been closed (e.g. you'll never receive another
        // request). Errors wiil return early...
        let done = match self.new_receiver.peek() {
            Ok(Async::Ready(None)) => true,
            Ok(_) => false,
            Err(_) => return Err(ProtoErrorKind::NoError.into()),
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
        return Ok(Async::NotReady);
    }
}

/// Always returns the specified io::Error to the remote Sender
struct ClientStreamErrored {
    // TODO: is there a better thing to grab here?
    error_msg: String,
    new_receiver:
        Peekable<StreamFuse<UnboundedReceiver<(Message, Complete<ProtoResult<Message>>)>>>,
}

impl Future for ClientStreamErrored {
    type Item = ();
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<(), Self::Error> {
        match self.new_receiver.poll() {
            Ok(Async::Ready(Some((_, complete)))) => {
                complete
                    .send(Err(ProtoErrorKind::Msg(self.error_msg.clone()).into()))
                    .expect("error notifying wait, possible future leak");

                task::current().notify();
                return Ok(Async::NotReady);
            }
            Ok(Async::Ready(None)) => return Ok(Async::Ready(())),            
            _ => return Err(ProtoErrorKind::NoError.into()),
        }
    }
}

enum ClientStreamOrError<S, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    MF: MessageFinalizer + 'static,
{
    Future(DnsFuture<S, MF>),
    Errored(ClientStreamErrored),
}

impl<S, MF> Future for ClientStreamOrError<S, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + 'static,
    MF: MessageFinalizer + 'static,
{
    type Item = ();
    type Error = ProtoError;

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
pub struct BasicDnsHandle {
    message_sender: UnboundedSender<(Message, Complete<ProtoResult<Message>>)>,
}

impl DnsHandle for BasicDnsHandle {
    type Error = ProtoError;

    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = Self::Error>> {
        let (complete, receiver) = oneshot::channel();
        let message_sender: &mut _ = &mut self.message_sender;

        // TODO: update to use Sink::send
        let receiver = match UnboundedSender::unbounded_send(message_sender, (message, complete)) {
            Ok(()) => receiver,
            Err(e) => {
                let (complete, receiver) = oneshot::channel();
                complete
                    .send(Err(
                        ProtoErrorKind::Msg(
                            format!("error sending to channel: {}", e),
                        ).into(),
                    ))
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
    type Error;

    /// Send a message via the channel in the client
    ///
    /// # Arguments
    ///
    /// * `message` - the fully constructed Message to send, note that most implementations of
    ///               will most likely be required to rewrite the QueryId, do no rely on that as
    ///               being stable.
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = Self::Error>>;
}
