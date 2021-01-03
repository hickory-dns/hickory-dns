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
use std::marker::Unpin;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_channel::mpsc;
use futures_util::stream::{Stream, StreamExt};
use futures_util::{future::Future, ready, FutureExt};
use log::{debug, warn};
use rand;
use rand::distributions::{Distribution, Standard};

use crate::error::*;
use crate::op::{Message, MessageFinalizer, OpCode};
use crate::xfer::{
    ignore_send, DnsClientStream, DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse,
    DnsResponseFuture, SerialMessage, CHANNEL_BUFFER_SIZE,
};
use crate::DnsStreamHandle;
use crate::Time;

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

struct ActiveRequest {
    // the completion is the channel for a response to the original request.
    // most requests pass a single Message response directly through to the completion
    //  this small vec will have no allocations, unless the requests is a DNS-SD request
    //  expecting more than one response.
    //  FIXME: change to a Bounded channel
    channel: mpsc::UnboundedSender<Result<DnsResponse, ProtoError>>,
    request_id: u16,
    request_options: DnsRequestOptions,
    timeout: Box<dyn Future<Output = ()> + Send + Unpin>,
}

impl ActiveRequest {
    fn new(
        channel: mpsc::UnboundedSender<Result<DnsResponse, ProtoError>>,
        request_id: u16,
        request_options: DnsRequestOptions,
        timeout: Box<dyn Future<Output = ()> + Send + Unpin>,
    ) -> Self {
        ActiveRequest {
            channel,
            request_id,
            request_options,
            timeout,
        }
    }

    /// polls the timeout and converts the error
    fn poll_timeout(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.timeout.poll_unpin(cx)
    }

    /// Returns true of the other side canceled the request
    fn is_canceled(&self) -> bool {
        self.channel.is_closed()
    }

    /// Adds the response to the request such that it can be later sent to the client
    fn send_response(&mut self, message: Message) {
        ignore_send(self.channel.unbounded_send(Ok(message.into())));
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
    fn send_error(&self, error: ProtoError) {
        ignore_send(self.channel.unbounded_send(Err(error)));
    }

    /// sends any registered responses to the requestor
    ///
    /// Any error sending will be logged and ignored. This must only be called after associating a response,
    ///   otherwise an error will always be returned.
    /// FIXME: is this necessary after stream API?
    fn complete(mut self) {
        self.channel.close_channel();
    }
}

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations. This should be used for underlying protocols that do not natively support
///  multiplexed sessions.
#[must_use = "futures do nothing unless polled"]
pub struct DnsMultiplexer<S, MF, D = Box<dyn DnsStreamHandle>>
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

impl<S, MF> DnsMultiplexer<S, MF, Box<dyn DnsStreamHandle>>
where
    S: DnsClientStream + Unpin + 'static,
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
        stream_handle: Box<dyn DnsStreamHandle>,
        signer: Option<Arc<MF>>,
    ) -> DnsMultiplexerConnect<F, S, MF>
    where
        F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
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
        stream_handle: Box<dyn DnsStreamHandle>,
        timeout_duration: Duration,
        signer: Option<Arc<MF>>,
    ) -> DnsMultiplexerConnect<F, S, MF>
    where
        F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
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
    fn drop_cancelled(&mut self, cx: &mut Context<'_>) {
        let mut canceled = Vec::<u16>::new();
        for (&id, ref mut active_req) in &mut self.active_requests {
            if active_req.is_canceled() {
                active_req.send_error(ProtoError::from("requestor canceled"));
                canceled.push(id);
            }

            // check for timeouts...
            match active_req.poll_timeout(cx) {
                Poll::Ready(()) => {
                    debug!("request timed out: {}", id);
                    active_req.send_error(ProtoError::from(ProtoErrorKind::Timeout));
                    canceled.push(id);
                }
                Poll::Pending => (),
            }
        }

        // drop all the canceled requests
        for id in canceled {
            if let Some(active_request) = self.active_requests.remove(&id) {
                active_request.complete();
            }
        }
    }

    /// creates random query_id, validates against all active queries
    fn next_random_query_id(&self) -> Result<u16, ProtoError> {
        let mut rand = rand::thread_rng();

        for _ in 0..100 {
            let id: u16 = Standard.sample(&mut rand); // the range is [0 ... u16::max]

            if !self.active_requests.contains_key(&id) {
                return Ok(id);
            }
        }

        Err(ProtoError::from(
            "id space exhausted, consider filing an issue",
        ))
    }

    /// Closes all outstanding completes with a closed stream error
    fn stream_closed_close_all(&mut self, error: ProtoError) {
        if !self.active_requests.is_empty() {
            warn!("stream {} error: {}", self.stream, error);
        } else {
            debug!("stream {} error: {}", self.stream, error);
        }

        for (_, active_request) in self.active_requests.drain() {
            active_request.send_error(error.clone());
            active_request.complete();
        }
    }
}

/// A wrapper for a future DnsExchange connection
#[must_use = "futures do nothing unless polled"]
pub struct DnsMultiplexerConnect<F, S, MF>
where
    F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
    S: Stream<Item = Result<SerialMessage, ProtoError>> + Unpin,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    stream: F,
    stream_handle: Option<Box<dyn DnsStreamHandle>>,
    timeout_duration: Duration,
    signer: Option<Arc<MF>>,
}

impl<F, S, MF> Future for DnsMultiplexerConnect<F, S, MF>
where
    F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
    S: DnsClientStream + Unpin + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type Output = Result<DnsMultiplexer<S, MF, Box<dyn DnsStreamHandle>>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let stream: S = ready!(self.stream.poll_unpin(cx))?;

        Poll::Ready(Ok(DnsMultiplexer {
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "{}", self.stream)
    }
}

impl<S, MF> DnsRequestSender for DnsMultiplexer<S, MF>
where
    S: DnsClientStream + Unpin + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseFuture {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        if self.active_requests.len() > CHANNEL_BUFFER_SIZE {
            return ProtoError::from(ProtoErrorKind::Busy).into();
        }

        let query_id = match self.next_random_query_id() {
            Ok(id) => id,
            Err(e) => return e.into(),
        };

        let (mut request, request_options) = request.into_parts();
        request.set_id(query_id);

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => now.as_secs(),
            Err(_) => return ProtoError::from("Current time is before the Unix epoch.").into(),
        };

        // TODO: truncates u64 to u32, error on overflow?
        let now = now as u32;

        // update messages need to be signed.
        if let OpCode::Update = request.op_code() {
            if let Some(ref signer) = self.signer {
                if let Err(e) = request.finalize::<MF>(signer.borrow(), now) {
                    debug!("could not sign message: {}", e);
                    return e.into();
                }
            }
        }

        // store a Timeout for this message before sending
        let timeout = S::Time::delay_for(self.timeout_duration);

        let (complete, receiver) = mpsc::unbounded();

        // send the message
        let active_request =
            ActiveRequest::new(complete, request.id(), request_options, Box::new(timeout));

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
                    Err(err) => return err.into(),
                };
            }
            Err(e) => {
                debug!(
                    "error message id: {} error: {}",
                    active_request.request_id(),
                    e
                );
                // complete with the error, don't add to the map of active requests
                return e.into();
            }
        }

        receiver.into()
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
    S: DnsClientStream + Unpin + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type Item = Result<(), ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Always drop the cancelled queries first
        self.drop_cancelled(cx);

        if self.is_shutdown && self.active_requests.is_empty() {
            debug!("stream is done: {}", self);
            return Poll::Ready(None);
        }

        // Collect all inbound requests, max 100 at a time for QoS
        //   by having a max we will guarantee that the client can't be DOSed in this loop
        // TODO: make the QoS configurable
        let mut messages_received = 0;
        for i in 0..QOS_MAX_RECEIVE_MSGS {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(buffer))) => {
                    messages_received = i;

                    //   deserialize or log decode_error
                    match buffer.to_message() {
                        Ok(message) => match self.active_requests.entry(message.id()) {
                            Entry::Occupied(mut request_entry) => {
                                // first add the response to the active_requests responses
                                let complete = {
                                    let active_request = request_entry.get_mut();
                                    active_request.send_response(message);

                                    // determine if this is complete
                                    !active_request.request_options().expects_multiple_responses
                                };

                                // now check if the request is complete
                                if complete {
                                    let active_request = request_entry.remove();
                                    active_request.complete();
                                }
                            }
                            Entry::Vacant(..) => debug!("unexpected request_id: {}", message.id()),
                        },
                        // TODO: return src address for diagnostics
                        Err(e) => debug!("error decoding message: {}", e),
                    }
                }
                Poll::Ready(err) => {
                    let err = match err {
                        Some(Err(e)) => e,
                        None => ProtoError::from("stream closed"),
                        _ => unreachable!(),
                    };

                    self.stream_closed_close_all(err);
                    self.is_shutdown = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => break,
            }
        }

        // If still active, then if the qos (for _ in 0..100 loop) limit
        // was hit then "yield". This'll make sure that the future is
        // woken up immediately on the next turn of the event loop.
        if messages_received == QOS_MAX_RECEIVE_MSGS {
            // FIXME: this was a task::current().notify(); is this right?
            cx.waker().wake_by_ref();
        }

        // Finally, return not ready to keep the 'driver task' alive.
        Poll::Pending
    }
}
