// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsMultiplexer` and associated types implement the state machines for sending DNS messages while using the underlying streams.

use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{self, Display};
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
    ignore_send, DnsClientStream, DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse,
    SerialMessage,
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
pub struct DnsMultiplexer<S, MF, D = Box<DnsStreamHandle>>
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

impl<S, MF> DnsMultiplexer<S, MF, Box<DnsStreamHandle>>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer,
{
    /// Spawns a new DnsMultiplexer Stream. This uses a default timeout of 5 seconds for all requests.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    #[allow(clippy::new_ret_no_self)]
    pub fn new<F>(
        stream: F,
        stream_handle: Box<DnsStreamHandle>,
        signer: Option<Arc<MF>>,
    ) -> DnsMultiplexerConnect<F, S, MF>
    where
        F: Future<Item = S, Error = ProtoError> + Send + 'static,
    {
        Self::with_timeout(stream, stream_handle, Duration::from_secs(5), signer)
    }

    /// Spawns a new DnsMultiplexer Stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of bytes that can be used to send/receive DNS messages
    ///              (see TcpClientStream or UdpClientStream)
    /// * `timeout_duration` - All requests may fail due to lack of response, this is the time to
    ///                        wait for a response before canceling the request.
    /// * `stream_handle` - The handle for the `stream` on which bytes can be sent/received.
    /// * `signer` - An optional signer for requests, needed for Updates with Sig0, otherwise not needed
    pub fn with_timeout<F>(
        stream: F,
        stream_handle: Box<DnsStreamHandle>,
        timeout_duration: Duration,
        signer: Option<Arc<MF>>,
    ) -> DnsMultiplexerConnect<F, S, MF>
    where
        F: Future<Item = S, Error = ProtoError> + Send + 'static,
    {
        DnsMultiplexerConnect {
            stream,
            stream_handle: Some(stream_handle),
            timeout_duration,
            signer,
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
                    debug!("request timed out: {}", id);
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
pub struct DnsMultiplexerConnect<F, S, MF>
where
    F: Future<Item = S, Error = ProtoError> + Send + 'static,
    S: Stream<Item = SerialMessage, Error = ProtoError>,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    stream: F,
    stream_handle: Option<Box<DnsStreamHandle>>,
    timeout_duration: Duration,
    signer: Option<Arc<MF>>,
}

impl<F, S, MF> Future for DnsMultiplexerConnect<F, S, MF>
where
    F: Future<Item = S, Error = ProtoError> + Send + 'static,
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type Item = DnsMultiplexer<S, MF, Box<DnsStreamHandle>>;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let stream: S = try_ready!(self.stream.poll());

        Ok(Async::Ready(DnsMultiplexer {
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

impl<S, MF> Display for DnsMultiplexer<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{}", self.stream)
    }
}

impl<S, MF> DnsRequestSender for DnsMultiplexer<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type DnsResponseFuture = DnsMultiplexerSerialResponse;

    fn send_message(&mut self, request: DnsRequest) -> Self::DnsResponseFuture {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // get next query_id
        let query_id: u16 = match self.next_random_query_id() {
            Async::Ready(id) => id,
            Async::NotReady => {
                return DnsMultiplexerSerialResponseInner::Err(Some(ProtoError::from(
                    "id space exhausted, consider filing an issue",
                ))).into()
            }
        };

        let (mut request, request_options) = request.unwrap();
        request.set_id(query_id);

        let now = match SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtoErrorKind::Message("Current time is before the Unix epoch.").into())
        {
            Ok(now) => now.as_secs(),
            Err(err) => return DnsMultiplexerSerialResponseInner::Err(Some(err)).into(),
        };

        // TODO: truncates u64 to u32, error on overflow?
        let now = now as u32;

        // update messages need to be signed.
        if let OpCode::Update = request.op_code() {
            if let Some(ref signer) = self.signer {
                if let Err(e) = request.finalize::<MF>(signer.borrow(), now) {
                    debug!("could not sign message: {}", e);
                    return DnsMultiplexerSerialResponseInner::Err(Some(e)).into();
                }
            }
        }

        // store a Timeout for this message before sending
        let timeout = Delay::new(Instant::now() + self.timeout_duration);

        let (complete, receiver) = oneshot::channel();

        // send the message
        let active_request = ActiveRequest::new(complete, request.id(), request_options, timeout);

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
                    Err(err) => return DnsMultiplexerSerialResponseInner::Err(Some(err)).into(),
                };
            }
            Err(e) => {
                debug!(
                    "error message id: {} error: {}",
                    active_request.request_id(),
                    e
                );
                // complete with the error, don't add to the map of active requests
                return DnsMultiplexerSerialResponseInner::Err(Some(e)).into();
            }
        }

        DnsMultiplexerSerialResponseInner::Completion(receiver).into()
    }

    fn error_response(error: ProtoError) -> Self::DnsResponseFuture {
        DnsMultiplexerSerialResponseInner::Err(Some(error)).into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl<S, MF> Stream for DnsMultiplexer<S, MF>
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
pub struct DnsMultiplexerSerialResponse(DnsMultiplexerSerialResponseInner);

impl DnsMultiplexerSerialResponse {
    /// Returns a new future with the oneshot completion
    pub fn completion(complete: oneshot::Receiver<ProtoResult<DnsResponse>>) -> Self {
        DnsMultiplexerSerialResponseInner::Completion(complete).into()
    }
}

impl Future for DnsMultiplexerSerialResponse {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl From<DnsMultiplexerSerialResponseInner> for DnsMultiplexerSerialResponse {
    fn from(inner: DnsMultiplexerSerialResponseInner) -> Self {
        DnsMultiplexerSerialResponse(inner)
    }
}

enum DnsMultiplexerSerialResponseInner {
    Completion(oneshot::Receiver<ProtoResult<DnsResponse>>),
    Err(Option<ProtoError>),
}

impl Future for DnsMultiplexerSerialResponseInner {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            // The inner type of the completion might have been an error
            //   we need to unwrap that, and translate to be the Future's error
            DnsMultiplexerSerialResponseInner::Completion(complete) => match try_ready!(
                complete
                    .poll()
                    .map_err(|_| ProtoError::from("the completion was canceled"))
            ) {
                Ok(response) => Ok(Async::Ready(response)),
                Err(err) => Err(err),
            },
            DnsMultiplexerSerialResponseInner::Err(err) => {
                Err(err.take().expect("cannot poll after complete"))
            }
        }
    }
}
