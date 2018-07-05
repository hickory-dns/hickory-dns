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
use std::fmt::{self, Display};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::stream::Stream;
use futures::sync::oneshot;
use futures::{task, Async, Future, Poll};
use rand;
use rand::distributions::{Distribution, Standard};
use smallvec::SmallVec;
use tokio_timer::Delay;

use error::*;
use op::{Message, MessageFinalizer, OpCode};
use xfer::{
    ignore_send, DnsClientStream, DnsRequestOptions, DnsResponse, SerialMessage,
    SerialMessageSender,
};
use DnsStreamHandle;

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

struct ActiveRequest {
    // the completion is the channel for a response to the original request
    completion: oneshot::Sender<Result<DnsResponse, ProtoError>>,
    request_id: u16,
    request_options: DnsRequestOptions,
    // most requests pass a single Message response directly through to the completion
    //  this small vec will have no allocations, unless the requests is a DNS-SD request
    //  expecting more than one response
    // TODO: change the completion above to a Stream, and don't hold messages...
    responses: SmallVec<[Message; 1]>,
    timeout: Delay,
}

impl ActiveRequest {
    fn new(
        completion: oneshot::Sender<Result<DnsResponse, ProtoError>>,
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
        ignore_send(self.completion.send(Err(error)));
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
///  implementations. This should be used for underlying protocols that do not natively support
///  multi-plexed sessions.
#[must_use = "futures do nothing unless polled"]
pub struct DnsFuture<S, MF, D = Box<DnsStreamHandle>>
where
    D: Send + 'static,
    S: DnsClientStream + 'static,
    MF: MessageFinalizer,
{
    stream: S,
    timeout_duration: Duration,
    stream_handle: D,
    active_requests: HashMap<u16, ActiveRequest>,
    signer: Option<Arc<MF>>,
    is_shutdown: bool,
}

impl<S, MF> DnsFuture<S, MF, Box<DnsStreamHandle>>
where
    S: DnsClientStream + 'static,
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
        stream_handle: Box<DnsStreamHandle>,
        signer: Option<Arc<MF>>,
    ) -> DnsFutureConnect<S, MF> {
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
        stream_handle: Box<DnsStreamHandle>,
        timeout_duration: Duration,
        signer: Option<Arc<MF>>,
    ) -> DnsFutureConnect<S, MF> {
        // TODO: remove box, see DnsExchange for Connect type
        DnsFutureConnect {
            stream,
            stream_handle: Some(stream_handle),
            timeout_duration,
            signer: signer,
        }
    }

    /// loop over active_requests and remove cancelled requests
    ///  this should free up space if we already had 4096 active requests
    fn drop_cancelled(&mut self) {
        let mut canceled = HashMap::<u16, ProtoError>::new();
        for (&id, ref mut active_req) in &mut self.active_requests {
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
            let id: u16 = Standard.sample(&mut rand); // the range is [0 ... u16::max]

            if !self.active_requests.contains_key(&id) {
                return Async::Ready(id);
            }
        }

        warn!("could not get next random query id, delaying");
        task::current().notify();
        Async::NotReady
    }

    /// Closes all outstanding completes with a closed stream error
    fn stream_closed_close_all(&mut self) {
        if !self.active_requests.is_empty() {
            warn!(
                "stream closed before response received: {}",
                self.stream.name_server_addr()
            );
        }

        let error = ProtoError::from("stream closed before response received");

        for (_, mut active_request) in self.active_requests.drain() {
            if active_request.responses.is_empty() {
                // complete the request, it's failed...
                active_request.complete_with_error(error.clone());
            } else {
                // this is a timeout waiting for multiple responses...
                active_request.complete();
            }
        }
    }
}

/// A wrapper for a future DnsExchange connection
#[must_use = "futures do nothing unless polled"]
pub struct DnsFutureConnect<S, MF>
where
    S: Stream<Item = SerialMessage, Error = io::Error>,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    stream: Box<Future<Item = S, Error = io::Error> + Send>,
    stream_handle: Option<Box<DnsStreamHandle>>,
    timeout_duration: Duration,
    signer: Option<Arc<MF>>,
}

impl<S, MF> Future for DnsFutureConnect<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type Item = DnsFuture<S, MF, Box<DnsStreamHandle>>;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let stream: S = try_ready!(self.stream.poll());

        Ok(Async::Ready(DnsFuture {
            stream,
            timeout_duration: self.timeout_duration,
            stream_handle: self
                .stream_handle
                .take()
                .expect("must not poll after complete"),
            active_requests: HashMap::new(),
            signer: self.signer.clone(),
            is_shutdown: false,
        }))
    }
}

impl<S, MF> Display for DnsFuture<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{}", self.stream)
    }
}

impl<S, MF> SerialMessageSender for DnsFuture<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type SerialResponse = DnsFutureSerialResponse;

    fn send_message(&mut self, request: SerialMessage) -> Self::SerialResponse {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // get next query_id
        let query_id: u16 = match self.next_random_query_id() {
            Async::Ready(id) => id,
            Async::NotReady => {
                return DnsFutureSerialResponseInner::Err(Some(ProtoError::from(
                    "id space exhausted, consider filing an issue",
                ))).into()
            }
        };

        // FIXME: clearly send_message shouldn't be a serial message at this point, make it a DnsRequest+dst
        let mut request = request
            .to_message()
            .expect("see FIXME above, don't be lazy... fix it!");
        request.set_id(query_id);

        let now = match SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtoErrorKind::Message("Current time is before the Unix epoch.").into())
        {
            Ok(now) => now.as_secs(),
            Err(err) => return DnsFutureSerialResponseInner::Err(Some(err)).into(),
        };

        let now = now as u32; // TODO: truncates u64 to u32, error on overflow?

        // update messages need to be signed.
        if let OpCode::Update = request.op_code() {
            if let Some(ref signer) = self.signer {
                if let Err(e) = request.finalize::<MF>(signer.borrow(), now) {
                    debug!("could not sign message: {}", e);
                    return DnsFutureSerialResponseInner::Err(Some(e.into())).into();
                }
            }
        }

        // store a Timeout for this message before sending
        let timeout = Delay::new(Instant::now() + self.timeout_duration);

        let (complete, receiver) = oneshot::channel();

        // send the message
        // FIXME: before merge to master, need options and DnsRequest
        let active_request = ActiveRequest::new(
            complete,
            request.id(),
            Default::default(), /*request.options().clone()*/
            timeout,
        );

        match request.to_vec() {
            Ok(buffer) => {
                debug!("sending message id: {}", active_request.request_id());
                let serial_message = SerialMessage::new(buffer, self.stream.name_server_addr());

                // add to the map -after- the client send b/c we don't want to put it in the map if
                //  we ended up returning an error from the send.
                match self.stream_handle.send(serial_message) {
                    Ok(()) => self
                        .active_requests
                        .insert(active_request.request_id(), active_request),
                    Err(err) => return DnsFutureSerialResponseInner::Err(Some(err.into())).into(),
                };
            }
            Err(e) => {
                debug!(
                    "error message id: {} error: {}",
                    active_request.request_id(),
                    e
                );
                // complete with the error, don't add to the map of active requests
                return DnsFutureSerialResponseInner::Err(Some(e)).into();
            }
        }

        DnsFutureSerialResponseInner::Completion(receiver).into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl<S, MF> Stream for DnsFuture<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type Item = ();
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // Always drop the cancelled queries first
        self.drop_cancelled();

        if self.is_shutdown && self.active_requests.is_empty() {
            debug!("stream is done: {}", self);
            return Ok(Async::Ready(None));
        }

        // Collect all inbound requests, max 100 at a time for QoS
        //   by having a max we will guarantee that the client can't be DOSed in this loop
        // TODO: make the QoS configurable
        let mut messages_received = 0;
        for i in 0..QOS_MAX_RECEIVE_MSGS {
            match self.stream.poll()? {
                Async::Ready(Some(buffer)) => {
                    messages_received = i;

                    //   deserialize or log decode_error
                    match buffer.to_message() {
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
                Async::Ready(None) => {
                    debug!("io_stream closed by other side: {}", self.stream);
                    self.stream_closed_close_all();
                    return Ok(Async::Ready(None));
                }
                Async::NotReady => break,
            }
        }

        // // Clean shutdown happens when all pending requests are done and the
        // // incoming channel has been closed (e.g. you'll never receive another
        // // request). Errors will return early...
        // let done = match self.new_receiver.peek() {
        //     Ok(Async::Ready(None)) => true,
        //     Ok(_) => false,
        //     Err(_) => return Err(ProtoErrorKind::NoError.into()),
        // };

        // // The
        // if self.active_requests.is_empty() && done {
        //     return Ok(Async::Ready(None)); // we are done
        // }

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

/// A future that resolves into a DnsResponse
#[must_use = "futures do nothing unless polled"]
pub struct DnsFutureSerialResponse(DnsFutureSerialResponseInner);

impl Future for DnsFutureSerialResponse {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl From<DnsFutureSerialResponseInner> for DnsFutureSerialResponse {
    fn from(inner: DnsFutureSerialResponseInner) -> Self {
        DnsFutureSerialResponse(inner)
    }
}

enum DnsFutureSerialResponseInner {
    Completion(oneshot::Receiver<ProtoResult<DnsResponse>>),
    Err(Option<ProtoError>),
}

impl Future for DnsFutureSerialResponseInner {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            // The inner type of the completion might have been an error
            //   we need to unwrap that, and translate to be the Future's error
            DnsFutureSerialResponseInner::Completion(complete) => match try_ready!(
                complete
                    .poll()
                    .map_err(|_| ProtoError::from("the completion was canceled"))
            ) {
                Ok(response) => Ok(Async::Ready(response)),
                Err(err) => Err(err),
            },
            DnsFutureSerialResponseInner::Err(err) => {
                Err(err.take().expect("cannot poll after complete"))
            }
        }
    }
}
//                     debug!("got message from receiver");

//                     // we have a new message to send
//                     match self.next_random_query_id() {
//                         Async::Ready(id) => Some(id),
//                         Async::NotReady => break,
//                     }
//                 }
//                 Ok(Async::Ready(None)) => {
//                     // We want to pop the nones off in the poll, to get rid of them.
//                     None
//                 }
//                 Ok(Async::NotReady) => {
//                     // we must break in the NotReady case as well, we don't want there to ever be a case where
//                     //  a message could arrive between peek and poll... i.e. a race condition where query_id
//                     //  would have been gotten
//                     break;
//                 }
//                 Err(()) => {
//                     warn!("receiver was shutdown?");
//                     break;
//                 }
//             };

//             // finally pop the reciever
//             match self.new_receiver.poll() {
//                 Ok(Async::Ready(Some((request, complete)))) => {
//                     let mut request: DnsRequest = request;

//                     // if there was a message, and the above succesion was succesful,
//                     //  register the new message, if not do not register, and set the complete to error.
//                     // getting a random query id, this mitigates potential cache poisoning.
//                     let query_id = query_id.expect("query_id should have been set above");
//                     request.set_id(query_id);

//                     let now = SystemTime::now()
//                         .duration_since(UNIX_EPOCH)
//                         .map_err(|_| {
//                             ProtoErrorKind::Message("Current time is before the Unix epoch.").into()
//                         })?
//                         .as_secs();
//                     let now = now as u32; // XXX: truncates u64 to u32.

//                     // update messages need to be signed.
//                     if let OpCode::Update = request.op_code() {
//                         if let Some(ref signer) = self.signer {
//                             if let Err(e) = request.finalize::<MF>(signer.borrow(), now) {
//                                 warn!("could not sign message: {}", e);
//                                 ignore_send(complete.send(Err(e.into())));
//                                 continue; // to the next message...
//                             }
//                         }
//                     }

//                     // store a Timeout for this message before sending
//                     let mut timeout = Delay::new(Instant::now() + self.timeout_duration);

//                     // make sure to register insterest in the Timeout
//                     match timeout.poll() {
//                         Ok(Async::Ready(_)) => {
//                             warn!("timeout fired before sending message!: {}", query_id);
//                             ignore_send(
//                                 complete
//                                     .send(Err(E::from(ProtoError::from(ProtoErrorKind::Timeout)))),
//                             );
//                             continue; // to the next message
//                         }
//                         Ok(Async::NotReady) => (), // this is the exepcted state...
//                         Err(e) => {
//                             error!("could not register interest in Timeout: {}", e);
//                             ignore_send(complete.send(Err(E::from(e.into()))));
//                             continue; // to the next message
//                         }
//                     }

//                     // send the message
//                     let active_request = ActiveRequest::new(
//                         complete,
//                         request.id(),
//                         request.options().clone(),
//                         timeout,
//                     );

//                     match request.unwrap().to_vec() {
//                         Ok(buffer) => {
//                             debug!("sending message id: {}", active_request.request_id());
//                             let serial_message =
//                                 SerialMessage::new(buffer, self.stream.name_server_addr());
//                             self.stream_handle.send(serial_message)?;

//                             // add to the map -after- the client send b/c we don't want to put it in the map if
//                             //  we ended up returning from the send.
//                             self.active_requests
//                                 .insert(active_request.request_id(), active_request);
//                         }
//                         Err(e) => {
//                             debug!(
//                                 "error message id: {} error: {}",
//                                 active_request.request_id(),
//                                 e
//                             );
//                             // complete with the error, don't add to the map of active requests
//                             active_request.complete_with_error(e);
//                         }
//                     }
//                 }
//                 Ok(_) => break,
//                 Err(()) => {
//                     warn!("receiver was shutdown?");
//                     break;
//                 }
//             }
//         }

//         // Collect all inbound requests, max 100 at a time for QoS
//         //   by having a max we will guarantee that the client can't be DOSed in this loop
//         // TODO: make the QoS configurable
//         let mut messages_received = 0;
//         for i in 0..QOS_MAX_RECEIVE_MSGS {
//             match self.stream.poll().map_err(|e| E::from(e.into()))? {
//                 Async::Ready(Some(buffer)) => {
//                     messages_received = i;

//                     //   deserialize or log decode_error
//                     match buffer.to_message() {
//                         Ok(message) => match self.active_requests.entry(message.id()) {
//                             Entry::Occupied(mut request_entry) => {
//                                 // first add the response to the active_requests responses
//                                 let complete = {
//                                     let mut active_request = request_entry.get_mut();
//                                     active_request.add_response(message);

//                                     // determine if this is complete
//                                     !active_request.request_options().expects_multiple_responses
//                                 };

//                                 // now check if the request is complete
//                                 if complete {
//                                     let mut active_request = request_entry.remove();
//                                     active_request.complete();
//                                 }
//                             }
//                             Entry::Vacant(..) => debug!("unexpected request_id: {}", message.id()),
//                         },
//                         // TODO: return src address for diagnostics
//                         Err(e) => debug!("error decoding message: {}", e),
//                     }
//                 }
//                 Async::Ready(None) | Async::NotReady => break,
//             }
//         }

//         // Clean shutdown happens when all pending requests are done and the
//         // incoming channel has been closed (e.g. you'll never receive another
//         // request). Errors will return early...
//         let done = match self.new_receiver.peek() {
//             Ok(Async::Ready(None)) => true,
//             Ok(_) => false,
//             Err(_) => return Err(E::from(ProtoErrorKind::NoError.into())),
//         };

//         if self.active_requests.is_empty() && done {
//             return Ok(().into()); // we are done
//         }

//         // If still active, then if the qos (for _ in 0..100 loop) limit
//         // was hit then "yield". This'll make sure that the future is
//         // woken up immediately on the next turn of the event loop.
//         if messages_received == QOS_MAX_RECEIVE_MSGS {
//             task::current().notify();
//         }

//         // Finally, return not ready to keep the 'driver task' alive.
//         Ok(Async::NotReady)
//     }
// }

// /// Always returns the specified io::Error to the remote Sender
// struct ClientStreamErrored<E>
// where
//     E: FromProtoError,
// {
//     error: E,
//     new_receiver: Peekable<
//         StreamFuse<UnboundedReceiver<(DnsRequest, oneshot::Sender<Result<DnsResponse, E>>)>>,
//     >,
// }

// impl<E> Future for ClientStreamErrored<E>
// where
//     E: FromProtoError,
// {
//     type Item = ();
//     type Error = E;

//     fn poll(&mut self) -> Poll<(), Self::Error> {
//         match self.new_receiver.poll() {
//             Ok(Async::Ready(Some((_, complete)))) => {
//                 // TODO: this error never seems to make it, the receiver closes early...
//                 ignore_send(complete.send(Err(self.error.clone())));

//                 task::current().notify();
//                 Ok(Async::NotReady)
//             }
//             Ok(Async::Ready(None)) => Ok(Async::Ready(())),
//             _ => Err(E::from(ProtoErrorKind::NoError.into())),
//         }
//     }
// }

// enum ClientStreamOrError<S, E, MF, D = Box<DnsStreamHandle<Error = E>>>
// where
//     D: Send + 'static,
//     S: DnsClientStream + 'static,
//     E: FromProtoError + Send,
//     MF: MessageFinalizer + Send + Sync + 'static,
// {
//     Future(DnsFuture<S, E, MF, D>),
//     Errored(ClientStreamErrored<E>),
// }

// impl<S, E, MF> Future for ClientStreamOrError<S, E, MF, Box<DnsStreamHandle<Error = E>>>
// where
//     S: DnsClientStream + 'static,
//     E: FromProtoError + Send + 'static,
//     MF: MessageFinalizer + Send + Sync + 'static,
// {
//     type Item = ();
//     type Error = E;

//     fn poll(&mut self) -> Poll<(), Self::Error> {
//         match *self {
//             ClientStreamOrError::Future(ref mut f) => Future::poll(f),
//             ClientStreamOrError::Errored(ref mut e) => e.poll(),
//         }
//     }
// }
