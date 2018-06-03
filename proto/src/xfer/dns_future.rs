// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsFuture` and associated types implement the state machines for sending DNS messages while using the underlying streams.

use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::stream::{Fuse as StreamFuse, Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{task, Async, Complete, Future, Poll};
use rand;
use rand::Rand;
use smallvec::SmallVec;
use tokio_executor;
use tokio_timer::Delay;

use error::*;
use op::{Message, MessageFinalizer, OpCode};
use xfer::{ignore_send, DnsRequest, DnsRequestOptions, DnsResponse};
use {BasicDnsHandle, DnsStreamHandle};

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

struct ActiveRequest<E: FromProtoError> {
    // the completion is the channel for a response to the original request
    completion: Complete<Result<DnsResponse, E>>,
    request_id: u16,
    request_options: DnsRequestOptions,
    // most requests pass a single Message response directly through to the completion
    //  this small vec will have no allocations, unless the requests is a DNS-SD request
    //  expecting more than one response
    responses: SmallVec<[Message; 1]>,
    timeout: Delay,
}

impl<E: FromProtoError> ActiveRequest<E> {
    fn new(
        completion: Complete<Result<DnsResponse, E>>,
        request_id: u16,
        request_options: DnsRequestOptions,
        timeout: Delay,
    ) -> Self {
        ActiveRequest {
            completion,
            request_id,
            request_options,
            // request,
            responses: SmallVec::new(),
            timeout,
        }
    }

    /// polls the timeout and converts the error
    fn poll_timeout(&mut self) -> Poll<(), ProtoError> {
        self.timeout.poll().map_err(ProtoError::from)
    }

    /// Returns true of the other side canceled the request
    fn is_canceled(&self) -> bool {
        self.completion.is_canceled()
    }

    /// Adds the response to the request such that it can be later sent to the client
    fn add_response(&mut self, message: Message) {
        self.responses.push(message);
    }

    /// the request id of the message that was sent
    fn request_id(&self) -> u16 {
        self.request_id
    }

    /// the request options from the message that was sent
    fn request_options(&self) -> &DnsRequestOptions {
        &self.request_options
    }

    /// Sends an error
    fn complete_with_error(self, error: ProtoError) {
        ignore_send(self.completion.send(Err(E::from(error))));
    }

    /// sends any registered responses to thethe requestor
    ///
    /// Any error sending will be logged and ignored. This must only be called after associating a response,
    ///   otherwise an error will alway be returned.
    fn complete(self) {
        if self.responses.is_empty() {
            self.complete_with_error("no responses received, should have timedout".into());
        } else {
            ignore_send(self.completion.send(Ok(self.responses.into())));
        }
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
    timeout_duration: Duration,
    // TODO: genericize and remove this Box
    stream_handle: Box<DnsStreamHandle<Error = E> + Send>,
    new_receiver:
        Peekable<StreamFuse<UnboundedReceiver<(DnsRequest, Complete<Result<DnsResponse, E>>)>>>,
    active_requests: HashMap<u16, ActiveRequest<E>>,
    signer: Option<Arc<MF>>,
}

impl<S, E, MF> DnsFuture<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + Send + 'static,
    E: FromProtoError + Send + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    /// Spawns a new DnsFuture Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn new(
        stream: Box<Future<Item = S, Error = io::Error> + Send>,
        stream_handle: Box<DnsStreamHandle<Error = E> + Send>,
        signer: Option<Arc<MF>>,
    ) -> BasicDnsHandle<E> {
        Self::with_timeout(stream, stream_handle, Duration::from_secs(5), signer)
    }

    /// Spawns a new DnsFuture Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///                        wait for a response before canceling the request.
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn with_timeout(
        stream: Box<Future<Item = S, Error = io::Error> + Send>,
        stream_handle: Box<DnsStreamHandle<Error = E> + Send>,
        timeout_duration: Duration,
        signer: Option<Arc<MF>>,
    ) -> BasicDnsHandle<E> {
        let (sender, rx) = unbounded();

        tokio_executor::spawn(
            stream
                .then(move |res| match res {
                    Ok(stream) => ClientStreamOrError::Future(DnsFuture {
                        stream: stream,
                        timeout_duration: timeout_duration,
                        stream_handle: stream_handle,
                        new_receiver: rx.fuse().peekable(),
                        active_requests: HashMap::new(),
                        signer: signer,
                    }),
                    Err(stream_error) => ClientStreamOrError::Errored(ClientStreamErrored {
                        error: E::from(stream_error.into()),
                        new_receiver: rx.fuse().peekable(),
                    }),
                })
                .map_err(|e| {
                    error!("error in Proto: {}", e);
                }),
        );

        BasicDnsHandle::new(sender)
    }

    /// loop over active_requests and remove cancelled requests
    ///  this should free up space if we already had 4096 active requests
    fn drop_cancelled(&mut self) {
        let mut canceled = HashMap::<u16, ProtoError>::new();
        for (&id, ref mut active_req /*(ref mut req, ref mut timeout)*/) in
            &mut self.active_requests
        {
            if active_req.is_canceled() {
                canceled.insert(id, ProtoError::from("requestor canceled"));
            }

            // check for timeouts...
            match active_req.poll_timeout() {
                Ok(Async::Ready(_)) => {
                    canceled.insert(id, ProtoError::from(ProtoErrorKind::Timeout));
                }
                Ok(Async::NotReady) => (),
                Err(e) => {
                    error!("unexpected error from timeout: {}", e);
                    canceled.insert(id, ProtoError::from("error registering timeout"));
                }
            }
        }

        // drop all the canceled requests
        for (id, error) in canceled {
            if let Some(active_request) = self.active_requests.remove(&id) {
                if active_request.responses.is_empty() {
                    // complete the request, it's failed...
                    active_request.complete_with_error(error);
                } else {
                    // this is a timeout waiting for multiple responses...
                    active_request.complete();
                }
            }
        }
    }

    /// creates random query_id, validates against all active queries
    fn next_random_query_id(&self) -> Async<u16> {
        let mut rand = rand::thread_rng();

        for _ in 0..100 {
            let id = u16::rand(&mut rand); // the range is [0 ... u16::max]

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
    S: Stream<Item = Vec<u8>, Error = io::Error> + Send + 'static,
    E: FromProtoError + Send + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
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
                Ok(Async::Ready(None)) => {
                    // We want to pop the nones off in the poll, to get rid of them.
                    None
                }
                Ok(Async::NotReady) => {
                    // we must break in the NotReady case as well, we don't want there to ever be a case where
                    //  a message could arrive between peek and poll... i.e. a race condition where query_id
                    //  would have been gotten
                    break;
                }
                Err(()) => {
                    warn!("receiver was shutdown?");
                    break;
                }
            };

            // finally pop the reciever
            match self.new_receiver.poll() {
                Ok(Async::Ready(Some((request, complete)))) => {
                    let mut request: DnsRequest = request;

                    // if there was a message, and the above succesion was succesful,
                    //  register the new message, if not do not register, and set the complete to error.
                    // getting a random query id, this mitigates potential cache poisoning.
                    let query_id = query_id.expect("query_id should have been set above");
                    request.set_id(query_id);

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| {
                            ProtoErrorKind::Message("Current time is before the Unix epoch.").into()
                        })?
                        .as_secs();
                    let now = now as u32; // XXX: truncates u64 to u32.

                    // update messages need to be signed.
                    if let OpCode::Update = request.op_code() {
                        if let Some(ref signer) = self.signer {
                            if let Err(e) = request.finalize::<MF>(signer.borrow(), now) {
                                warn!("could not sign message: {}", e);
                                ignore_send(complete.send(Err(e.into())));
                                continue; // to the next message...
                            }
                        }
                    }

                    // store a Timeout for this message before sending
                    let mut timeout = Delay::new(Instant::now() + self.timeout_duration);

                    // make sure to register insterest in the Timeout
                    match timeout.poll() {
                        Ok(Async::Ready(_)) => {
                            warn!("timeout fired before sending message!: {}", query_id);
                            ignore_send(
                                complete
                                    .send(Err(E::from(ProtoError::from(ProtoErrorKind::Timeout)))),
                            );
                            continue; // to the next message
                        }
                        Ok(Async::NotReady) => (), // this is the exepcted state...
                        Err(e) => {
                            error!("could not register interest in Timeout: {}", e);
                            ignore_send(complete.send(Err(E::from(e.into()))));
                            continue; // to the next message
                        }
                    }

                    // send the message
                    let active_request = ActiveRequest::new(
                        complete,
                        request.id(),
                        request.options().clone(),
                        timeout,
                    );

                    match request.unwrap().to_vec() {
                        Ok(buffer) => {
                            debug!("sending message id: {}", active_request.request_id());
                            self.stream_handle.send(buffer)?;

                            // add to the map -after- the client send b/c we don't want to put it in the map if
                            //  we ended up returning from the send.
                            self.active_requests
                                .insert(active_request.request_id(), active_request);
                        }
                        Err(e) => {
                            debug!(
                                "error message id: {} error: {}",
                                active_request.request_id(),
                                e
                            );
                            // complete with the error, don't add to the map of active requests
                            active_request.complete_with_error(e);
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
                        Ok(message) => match self.active_requests.entry(message.id()) {
                            Entry::Occupied(mut request_entry) => {
                                // first add the response to the active_requests responses
                                let complete = {
                                    let mut active_request = request_entry.get_mut();
                                    active_request.add_response(message);

                                    // determine if this is complete
                                    !active_request.request_options().expects_multiple_responses
                                };

                                // now check if the request is complete
                                if complete {
                                    let mut active_request = request_entry.remove();
                                    active_request.complete();
                                }
                            }
                            Entry::Vacant(..) => debug!("unexpected request_id: {}", message.id()),
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
        // request). Errors will return early...
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
    error: E,
    new_receiver:
        Peekable<StreamFuse<UnboundedReceiver<(DnsRequest, Complete<Result<DnsResponse, E>>)>>>,
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
                // TODO: this error never seems to make it, the receiver closes early...
                ignore_send(complete.send(Err(self.error.clone())));

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
    S: Stream<Item = Vec<u8>, Error = io::Error> + Send + 'static,
    E: FromProtoError + Send,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    Future(DnsFuture<S, E, MF>),
    Errored(ClientStreamErrored<E>),
}

impl<S, E, MF> Future for ClientStreamOrError<S, E, MF>
where
    S: Stream<Item = Vec<u8>, Error = io::Error> + Send + 'static,
    E: FromProtoError + Send + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
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
