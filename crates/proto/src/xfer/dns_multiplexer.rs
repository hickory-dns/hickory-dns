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
use crate::op::{MessageFinalizer, MessageVerifier};
use crate::xfer::{
    ignore_send, BufDnsStreamHandle, DnsClientStream, DnsRequest, DnsRequestSender, DnsResponse,
    DnsResponseStream, SerialMessage, CHANNEL_BUFFER_SIZE,
};
use crate::DnsStreamHandle;
use crate::Time;

const QOS_MAX_RECEIVE_MSGS: usize = 100; // max number of messages to receive from the UDP socket

struct ActiveRequest {
    // the completion is the channel for a response to the original request
    completion: mpsc::Sender<Result<DnsResponse, ProtoError>>,
    request_id: u16,
    timeout: Box<dyn Future<Output = ()> + Send + Unpin>,
    verifier: Option<MessageVerifier>,
}

impl ActiveRequest {
    fn new(
        completion: mpsc::Sender<Result<DnsResponse, ProtoError>>,
        request_id: u16,
        timeout: Box<dyn Future<Output = ()> + Send + Unpin>,
        verifier: Option<MessageVerifier>,
    ) -> Self {
        Self {
            completion,
            request_id,
            // request,
            timeout,
            verifier,
        }
    }

    /// polls the timeout and converts the error
    fn poll_timeout(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.timeout.poll_unpin(cx)
    }

    /// Returns true of the other side canceled the request
    fn is_canceled(&self) -> bool {
        self.completion.is_closed()
    }

    /// the request id of the message that was sent
    fn request_id(&self) -> u16 {
        self.request_id
    }

    /// Sends an error
    fn complete_with_error(mut self, error: ProtoError) {
        ignore_send(self.completion.try_send(Err(error)));
    }
}

/// A DNS Client implemented over futures-rs.
///
/// This Client is generic and capable of wrapping UDP, TCP, and other underlying DNS protocol
///  implementations. This should be used for underlying protocols that do not natively support
///  multiplexed sessions.
#[must_use = "futures do nothing unless polled"]
pub struct DnsMultiplexer<S, MF>
where
    S: DnsClientStream + 'static,
    MF: MessageFinalizer,
{
    stream: S,
    timeout_duration: Duration,
    stream_handle: BufDnsStreamHandle,
    active_requests: HashMap<u16, ActiveRequest>,
    signer: Option<Arc<MF>>,
    is_shutdown: bool,
}

impl<S, MF> DnsMultiplexer<S, MF>
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
        stream_handle: BufDnsStreamHandle,
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
        stream_handle: BufDnsStreamHandle,
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
        let mut canceled = HashMap::<u16, ProtoError>::new();
        for (&id, ref mut active_req) in &mut self.active_requests {
            if active_req.is_canceled() {
                canceled.insert(id, ProtoError::from("requestor canceled"));
            }

            // check for timeouts...
            match active_req.poll_timeout(cx) {
                Poll::Ready(()) => {
                    debug!("request timed out: {}", id);
                    canceled.insert(id, ProtoError::from(ProtoErrorKind::Timeout));
                }
                Poll::Pending => (),
            }
        }

        // drop all the canceled requests
        for (id, error) in canceled {
            if let Some(active_request) = self.active_requests.remove(&id) {
                // complete the request, it's failed...
                active_request.complete_with_error(error);
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
            // complete the request, it's failed...
            active_request.complete_with_error(error.clone());
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
    stream_handle: Option<BufDnsStreamHandle>,
    timeout_duration: Duration,
    signer: Option<Arc<MF>>,
}

impl<F, S, MF> Future for DnsMultiplexerConnect<F, S, MF>
where
    F: Future<Output = Result<S, ProtoError>> + Send + Unpin + 'static,
    S: DnsClientStream + Unpin + 'static,
    MF: MessageFinalizer + Send + Sync + 'static,
{
    type Output = Result<DnsMultiplexer<S, MF>, ProtoError>;

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
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
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

        let (mut request, _) = request.into_parts();
        request.set_id(query_id);

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => now.as_secs(),
            Err(_) => return ProtoError::from("Current time is before the Unix epoch.").into(),
        };

        // TODO: truncates u64 to u32, error on overflow?
        let now = now as u32;

        let mut verifier = None;
        if let Some(ref signer) = self.signer {
            if signer.should_finalize_message(&request) {
                match request.finalize::<MF>(signer.borrow(), now) {
                    Ok(answer_verifier) => verifier = answer_verifier,
                    Err(e) => {
                        debug!("could not sign message: {}", e);
                        return e.into();
                    }
                }
            }
        }

        // store a Timeout for this message before sending
        let timeout = S::Time::delay_for(self.timeout_duration);

        let (complete, receiver) = mpsc::channel(CHANNEL_BUFFER_SIZE);

        // send the message
        let active_request =
            ActiveRequest::new(complete, request.id(), Box::new(timeout), verifier);

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
                                // send the response, complete the request...
                                let active_request = request_entry.get_mut();
                                if let Some(ref mut verifier) = active_request.verifier {
                                    ignore_send(
                                        active_request
                                            .completion
                                            .try_send(verifier(buffer.bytes())),
                                    );
                                } else {
                                    ignore_send(
                                        active_request.completion.try_send(Ok(message.into())),
                                    );
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::op::message::NoopMessageFinalizer;
    use crate::op::op_code::OpCode;
    use crate::op::{Message, MessageType, Query};
    use crate::rr::record_type::RecordType;
    use crate::rr::{DNSClass, Name, RData, Record};
    use crate::serialize::binary::BinEncodable;
    use crate::xfer::StreamReceiver;
    use crate::xfer::{DnsClientStream, DnsRequestOptions};
    use futures_util::future;
    use futures_util::stream::TryStreamExt;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    struct MockClientStream {
        messages: Vec<Message>,
        addr: SocketAddr,
        id: Option<u16>,
        receiver: Option<StreamReceiver>,
    }

    impl MockClientStream {
        fn new(
            mut messages: Vec<Message>,
            addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = Result<Self, ProtoError>> + Send>> {
            messages.reverse(); // so we can pop() and get messages in order
            Box::pin(future::ok(Self {
                messages,
                addr,
                id: None,
                receiver: None,
            }))
        }
    }

    impl fmt::Display for MockClientStream {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            write!(formatter, "TestClientStream")
        }
    }

    impl Stream for MockClientStream {
        type Item = Result<SerialMessage, ProtoError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let id = if let Some(id) = self.id {
                id
            } else {
                let serial = ready!(self
                    .receiver
                    .as_mut()
                    .expect("should only be polled after receiver has been set")
                    .poll_next_unpin(cx));
                let message = serial.unwrap().to_message().unwrap();
                self.id = Some(message.id());
                message.id()
            };

            if let Some(mut message) = self.messages.pop() {
                message.set_id(id);
                Poll::Ready(Some(Ok(SerialMessage::new(
                    message.to_bytes().unwrap(),
                    self.addr,
                ))))
            } else {
                Poll::Pending
            }
        }
    }

    impl DnsClientStream for MockClientStream {
        type Time = crate::TokioTime;

        fn name_server_addr(&self) -> SocketAddr {
            self.addr
        }
    }

    async fn get_mocked_multiplexer(
        mock_response: Vec<Message>,
    ) -> DnsMultiplexer<MockClientStream, NoopMessageFinalizer> {
        let addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        let mock_response = MockClientStream::new(mock_response, addr);
        let (handler, receiver) = BufDnsStreamHandle::new(addr);
        let mut multiplexer =
            DnsMultiplexer::with_timeout(mock_response, handler, Duration::from_millis(100), None)
                .await
                .unwrap();

        multiplexer.stream.receiver = Some(receiver); // so it can get the correct request id

        multiplexer
    }

    fn a_query_answer() -> (DnsRequest, Vec<Message>) {
        let name = Name::from_ascii("www.example.com").unwrap();

        let mut msg = Message::new();
        msg.add_query({
            let mut query = Query::query(name.clone(), RecordType::A);
            query.set_query_class(DNSClass::IN);
            query
        })
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);

        let query = msg.clone();
        msg.set_message_type(MessageType::Response).add_answer(
            Record::new()
                .set_name(name)
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
                .clone(),
        );
        (
            DnsRequest::new(query, DnsRequestOptions::default()),
            vec![msg],
        )
    }

    fn axfr_query() -> Message {
        let name = Name::from_ascii("example.com").unwrap();

        let mut msg = Message::new();
        msg.add_query({
            let mut query = Query::query(name, RecordType::AXFR);
            query.set_query_class(DNSClass::IN);
            query
        })
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
        msg
    }

    fn axfr_response() -> Vec<Record> {
        use crate::rr::rdata::*;
        let origin = Name::from_ascii("example.com").unwrap();
        let soa = Record::new()
            .set_name(origin.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_data(Some(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            ))))
            .clone();

        vec![
            soa.clone(),
            Record::new()
                .set_name(origin.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::NS)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NS(
                    Name::parse("a.iana-servers.net.", None).unwrap(),
                )))
                .clone(),
            Record::new()
                .set_name(origin.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::NS)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::NS(
                    Name::parse("b.iana-servers.net.", None).unwrap(),
                )))
                .clone(),
            Record::new()
                .set_name(origin.clone())
                .set_ttl(86400)
                .set_rr_type(RecordType::A)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::A(Ipv4Addr::new(93, 184, 216, 34))))
                .clone(),
            Record::new()
                .set_name(origin)
                .set_ttl(86400)
                .set_rr_type(RecordType::AAAA)
                .set_dns_class(DNSClass::IN)
                .set_data(Some(RData::AAAA(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                ))))
                .clone(),
            soa,
        ]
    }

    fn axfr_query_answer() -> (DnsRequest, Vec<Message>) {
        let mut msg = axfr_query();

        let query = msg.clone();
        msg.set_message_type(MessageType::Response)
            .insert_answers(axfr_response());
        (
            DnsRequest::new(query, DnsRequestOptions::default()),
            vec![msg],
        )
    }

    fn axfr_query_answer_multi() -> (DnsRequest, Vec<Message>) {
        let base = axfr_query();

        let query = base.clone();
        let mut rr = axfr_response();
        let rr2 = rr.split_off(3);
        let mut msg1 = base.clone();
        msg1.set_message_type(MessageType::Response)
            .insert_answers(rr);
        let mut msg2 = base;
        msg2.set_message_type(MessageType::Response)
            .insert_answers(rr2);
        (
            DnsRequest::new(query, DnsRequestOptions::default()),
            vec![msg1, msg2],
        )
    }

    #[tokio::test]
    async fn test_multiplexer_a() {
        let (query, answer) = a_query_answer();
        let mut multiplexer = get_mocked_multiplexer(answer).await;
        let response = multiplexer.send_message(query);
        let response = tokio::select! {
            _ = multiplexer.next() => {
                // polling multiplexer to make it run
                panic!("should never end")
            },
            r = response.try_collect::<Vec<_>>() => r.unwrap(),
        };
        assert_eq!(response.len(), 1);
    }

    #[tokio::test]
    async fn test_multiplexer_axfr() {
        let (query, answer) = axfr_query_answer();
        let mut multiplexer = get_mocked_multiplexer(answer).await;
        let response = multiplexer.send_message(query);
        let response = tokio::select! {
            _ = multiplexer.next() => {
                // polling multiplexer to make it run
                panic!("should never end")
            },
            r = response.try_collect::<Vec<_>>() => r.unwrap(),
        };
        assert_eq!(response.len(), 1);
        assert_eq!(response[0].answers().len(), axfr_response().len());
    }

    #[tokio::test]
    async fn test_multiplexer_axfr_multi() {
        let (query, answer) = axfr_query_answer_multi();
        let mut multiplexer = get_mocked_multiplexer(answer).await;
        let response = multiplexer.send_message(query);
        let response = tokio::select! {
            _ = multiplexer.next() => {
                // polling multiplexer to make it run
                panic!("should never end")
            },
            r = response.try_collect::<Vec<_>>() => r.unwrap(),
        };
        assert_eq!(response.len(), 2);
        assert_eq!(
            response.iter().map(|m| m.answers().len()).sum::<usize>(),
            axfr_response().len()
        );
    }
}
