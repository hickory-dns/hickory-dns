// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::{sync::Arc, vec::Vec};
use core::fmt::{self, Display};
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::HashSet;
use std::io;

use futures_util::{
    FutureExt, Stream, StreamExt, future::Future, pin_mut, stream::FuturesUnordered,
};
use tracing::{debug, trace, warn};

use crate::error::{ProtoError, ProtoErrorKind};
use crate::op::{DnsRequest, DnsResponse, Message, MessageSigner, SerialMessage};
use crate::runtime::{RuntimeProvider, Time};
use crate::udp::udp_stream::NextRandomUdpSocket;
use crate::udp::{DEFAULT_RETRY_FLOOR, DnsUdpSocket, MAX_RECEIVE_BUFFER_SIZE};
use crate::xfer::{DnsRequestSender, DnsResponseStream};

/// A UDP client stream of DNS binary packets.
///
/// It is expected that the resolver wrapper will be responsible for creating and managing a new UDP
/// client stream such that each request would have a random port. This is to avoid potential cache
/// poisoning due to UDP spoofing attacks.
#[must_use = "futures do nothing unless polled"]
pub struct UdpClientStream<P> {
    name_server: SocketAddr,
    timeout: Duration,
    is_shutdown: bool,
    signer: Option<Arc<dyn MessageSigner>>,
    bind_addr: Option<SocketAddr>,
    avoid_local_ports: Arc<HashSet<u16>>,
    os_port_selection: bool,
    provider: P,
    max_retries: u8,
    retry_interval_floor: Duration,
}

impl<P: RuntimeProvider> UdpClientStream<P> {
    /// Construct a new [`UdpClientStream`] via a [`UdpClientStreamBuilder`].
    pub fn builder(name_server: SocketAddr, provider: P) -> UdpClientStreamBuilder<P> {
        UdpClientStreamBuilder {
            name_server,
            timeout: None,
            signer: None,
            bind_addr: None,
            avoid_local_ports: Arc::default(),
            os_port_selection: false,
            provider,
            max_retries: 3,
            // This is the default value to use for the retry interval floor, which acts as a lower
            // bound on the retry interval.
            retry_interval_floor: DEFAULT_RETRY_FLOOR,
        }
    }
}

impl<P> Display for UdpClientStream<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "UDP({})", self.name_server)
    }
}

impl<P: RuntimeProvider> DnsRequestSender for UdpClientStream<P> {
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        let retry_interval_time = request.options().retry_interval;
        let request = UdpRequest::new(request, self);

        let max_retries = self.max_retries;
        let retry_interval = if retry_interval_time < self.retry_interval_floor {
            self.retry_interval_floor
        } else {
            retry_interval_time
        };

        P::Timer::timeout(
            self.timeout,
            retry::<P>(request, retry_interval, max_retries.into()),
        )
        .into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

// TODO: is this impl necessary? there's nothing being driven here...
impl<P> Stream for UdpClientStream<P> {
    type Item = Result<(), ProtoError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Technically the Stream doesn't actually do anything.
        if self.is_shutdown {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(())))
        }
    }
}

/// Request context for data send_udp_message needs via the retry handler closure
struct UdpRequest<P> {
    avoid_local_ports: Arc<HashSet<u16>>,
    name_server: SocketAddr,
    request: DnsRequest,
    provider: P,
    signer: Option<Arc<dyn MessageSigner>>,
    now: u64,
    bind_addr: Option<SocketAddr>,
    os_port_selection: bool,
    case_randomization: bool,
    recv_buf_size: usize,
}

impl<P: RuntimeProvider> UdpRequest<P> {
    fn new(request: DnsRequest, stream: &UdpClientStream<P>) -> Self {
        Self {
            avoid_local_ports: stream.avoid_local_ports.clone(),
            recv_buf_size: MAX_RECEIVE_BUFFER_SIZE.min(request.max_payload() as usize),
            case_randomization: request.options().case_randomization,
            name_server: stream.name_server,
            // Only smuggle in the signer if we are going to use it.
            signer: match &stream.signer {
                Some(signer) if signer.should_sign_message(&request) => stream.signer.clone(),
                _ => None,
            },
            request,
            provider: stream.provider.clone(),
            now: P::Timer::current_time(),
            bind_addr: stream.bind_addr,
            os_port_selection: stream.os_port_selection,
        }
    }
}

impl<P: RuntimeProvider> Request for UdpRequest<P> {
    async fn send(&self) -> Result<DnsResponse, ProtoError> {
        let original_query = self.request.original_query();
        let mut request = self.request.clone();

        let mut verifier = None;
        if let Some(signer) = &self.signer {
            match request.finalize(&**signer, self.now) {
                Ok(answer_verifier) => verifier = answer_verifier,
                Err(e) => {
                    debug!("could not sign message: {}", e);
                    return Err(e);
                }
            }
        }

        let request_bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return Err(err),
        };

        let msg_id = request.id();
        let msg = SerialMessage::new(request_bytes, self.name_server);
        let addr = msg.addr();
        let final_message = match msg.to_message() {
            Ok(m) => m,
            Err(e) => return Err(e),
        };
        debug!(%final_message, "final message");

        let socket = NextRandomUdpSocket::new(
            addr,
            self.bind_addr,
            self.avoid_local_ports.clone(),
            self.os_port_selection,
            self.provider.clone(),
        )
        .await?;

        let bytes = msg.bytes();
        let len_sent: usize = socket.send_to(bytes, addr).await?;

        if bytes.len() != len_sent {
            return Err(ProtoError::from(format!(
                "Not all bytes of message sent, {} of {}",
                len_sent,
                bytes.len()
            )));
        }

        // Create the receive buffer.
        trace!(
            recv_buf_size = self.recv_buf_size,
            "creating UDP receive buffer"
        );
        let mut recv_buf = vec![0; self.recv_buf_size];

        // Try to process up to 3 responses
        for _ in 0..3 {
            let (len, src) = socket.recv_from(&mut recv_buf).await?;

            // Copy the slice of read bytes.
            let response_bytes = &recv_buf[0..len];
            let response_buffer = Vec::from(response_bytes);

            // compare expected src to received packet
            let request_target = msg.addr();

            // Comparing the IP and Port directly as internal information about the link is stored with the IpAddr, see https://github.com/hickory-dns/hickory-dns/issues/2081
            if src.ip().to_canonical() != request_target.ip().to_canonical()
                || src.port() != request_target.port()
            {
                warn!(
                    "ignoring response from {}:{} because it does not match name_server: {}:{}.",
                    src.ip().to_canonical(),
                    src.port(),
                    request_target.ip().to_canonical(),
                    request_target.port(),
                );

                // await an answer from the correct NameServer
                continue;
            }

            let mut response = match DnsResponse::from_buffer(response_buffer) {
                Ok(response) => response,
                Err(e) => {
                    // on errors deserializing, continue
                    warn!("dropped malformed message waiting for id: {msg_id} err: {e}");
                    continue;
                }
            };

            // Validate the message id in the response matches the value chosen for the query.
            if msg_id != response.id() {
                // on wrong id, attempted poison?
                warn!(
                    "expected message id: {} got: {}, dropped",
                    msg_id,
                    response.id()
                );

                return Err(ProtoErrorKind::BadTransactionId.into());
            }

            // Validate the returned query name.
            //
            // This currently checks that each response query name was present in the original query, but not that
            // every original question is present.
            //
            // References:
            //
            // RFC 1035 7.3:
            //
            // The next step is to match the response to a current resolver request.
            // The recommended strategy is to do a preliminary matching using the ID
            // field in the domain header, and then to verify that the question section
            // corresponds to the information currently desired.
            //
            // RFC 1035 7.4:
            //
            // In general, we expect a resolver to cache all data which it receives in
            // responses since it may be useful in answering future client requests.
            // However, there are several types of data which should not be cached:
            //
            // ...
            //
            //  - RR data in responses of dubious reliability.  When a resolver
            // receives unsolicited responses or RR data other than that
            // requested, it should discard it without caching it.
            let request_message = Message::from_vec(msg.bytes())?;
            let request_queries = request_message.queries();
            let response_queries = response.queries_mut();

            let question_matches = response_queries
                .iter()
                .all(|elem| request_queries.contains(elem));
            if self.case_randomization
                && question_matches
                && !response_queries.iter().all(|elem| {
                    request_queries
                        .iter()
                        .any(|req_q| req_q == elem && req_q.name().eq_case(elem.name()))
                })
            {
                warn!(
                    "case of question section did not match: we expected '{request_queries:?}', but received '{response_queries:?}' from server {src}"
                );
                return Err(ProtoErrorKind::QueryCaseMismatch.into());
            }
            if !question_matches {
                warn!(
                    "detected forged question section: we expected '{request_queries:?}', but received '{response_queries:?}' from server {src}"
                );
                continue;
            }

            // overwrite the query with the original query if case randomization may have been used
            if self.case_randomization {
                if let Some(original_query) = original_query {
                    for response_query in response_queries.iter_mut() {
                        if response_query == original_query {
                            *response_query = original_query.clone();
                        }
                    }
                }
            }

            debug!("received message id: {}", response.id());
            if let Some(mut verifier) = verifier {
                return verifier(response_bytes);
            } else {
                return Ok(response);
            }
        }

        Err("udp receive attempts exceeded".into())
    }
}

/// A builder to create a UDP client stream.
///
/// This is created by [`UdpClientStream::builder`].
pub struct UdpClientStreamBuilder<P> {
    name_server: SocketAddr,
    timeout: Option<Duration>,
    signer: Option<Arc<dyn MessageSigner>>,
    bind_addr: Option<SocketAddr>,
    avoid_local_ports: Arc<HashSet<u16>>,
    os_port_selection: bool,
    provider: P,
    max_retries: u8,
    retry_interval_floor: Duration,
}

impl<P> UdpClientStreamBuilder<P> {
    /// Sets the connection timeout.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the message finalizer to be applied to queries.
    pub fn with_signer(self, signer: Option<Arc<dyn MessageSigner>>) -> Self {
        Self {
            name_server: self.name_server,
            timeout: self.timeout,
            signer,
            bind_addr: self.bind_addr,
            avoid_local_ports: self.avoid_local_ports,
            os_port_selection: self.os_port_selection,
            provider: self.provider,
            max_retries: self.max_retries,
            retry_interval_floor: self.retry_interval_floor,
        }
    }

    /// Sets the local socket address to connect from.
    ///
    /// If the port number is 0, a random port number will be chosen to defend against spoofing
    /// attacks. If the port number is nonzero, it will be used instead.
    pub fn with_bind_addr(mut self, bind_addr: Option<SocketAddr>) -> Self {
        self.bind_addr = bind_addr;
        self
    }

    /// Configures a list of local UDP ports that should not be used when making outgoing
    /// connections.
    pub fn avoid_local_ports(mut self, avoid_local_ports: Arc<HashSet<u16>>) -> Self {
        self.avoid_local_ports = avoid_local_ports;
        self
    }

    /// Configures that OS should provide the ephemeral port, not the Hickory DNS
    pub fn with_os_port_selection(mut self, os_port_selection: bool) -> Self {
        self.os_port_selection = os_port_selection;
        self
    }

    /// Sets the maximum number of retries for a single request
    pub fn with_max_retries(mut self, max_retries: u8) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the retry interval floor
    pub fn with_retry_interval_floor(mut self, floor: u64) -> Self {
        self.retry_interval_floor = Duration::from_millis(floor);
        self
    }

    /// Construct a new UDP client stream.
    ///
    /// Returns a future that outputs the client stream.
    pub fn build(self) -> UdpClientConnect<P> {
        UdpClientConnect {
            name_server: self.name_server,
            timeout: self.timeout.unwrap_or(Duration::from_secs(5)),
            signer: self.signer,
            bind_addr: self.bind_addr,
            avoid_local_ports: self.avoid_local_ports.clone(),
            os_port_selection: self.os_port_selection,
            provider: self.provider,
            max_retries: self.max_retries,
            retry_interval_floor: self.retry_interval_floor,
        }
    }
}

/// A future that resolves to an UdpClientStream
pub struct UdpClientConnect<P> {
    name_server: SocketAddr,
    timeout: Duration,
    signer: Option<Arc<dyn MessageSigner>>,
    bind_addr: Option<SocketAddr>,
    avoid_local_ports: Arc<HashSet<u16>>,
    os_port_selection: bool,
    provider: P,
    max_retries: u8,
    retry_interval_floor: Duration,
}

impl<P: RuntimeProvider> Future for UdpClientConnect<P> {
    type Output = Result<UdpClientStream<P>, io::Error>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: this doesn't need to be a future?
        Poll::Ready(Ok(UdpClientStream {
            name_server: self.name_server,
            is_shutdown: false,
            timeout: self.timeout,
            signer: self.signer.take(),
            bind_addr: self.bind_addr,
            avoid_local_ports: self.avoid_local_ports.clone(),
            os_port_selection: self.os_port_selection,
            provider: self.provider.clone(),
            max_retries: self.max_retries,
            retry_interval_floor: self.retry_interval_floor,
        }))
    }
}

/// This implements a retry handler for tasks that might not complete successfully (e.g.,
/// DNS requests made via UDP.) It starts a task future immediately, then every
/// retry_interval_time period up to a maximum of max_tasks. It will immediately return
/// the first task that completes successfully, or an error if no tasks succeed.
/// It does not implement an overall timeout to bound the work.
async fn retry<Provider: RuntimeProvider>(
    request: impl Request,
    retry_interval_time: Duration,
    max_tasks: usize,
) -> Result<DnsResponse, ProtoError> {
    let mut futures = FuturesUnordered::new();

    let retry_timer = Provider::Timer::delay_for(retry_interval_time).fuse();
    pin_mut!(retry_timer);

    futures.push(request.send());
    let mut tasks = 1;

    loop {
        futures_util::select! {
            result = futures.next() => {
                match result {
                    Some(result) => return result,
                    None => return Err(ProtoError::from("no tasks successful")),
                }
            }
            _ = &mut retry_timer => {
                if tasks < max_tasks {
                    tasks += 1;
                    futures.push(request.send());
                    retry_timer.set(Provider::Timer::delay_for(retry_interval_time).fuse());
                }
            }
        }
    }
}

trait Request {
    async fn send(&self) -> Result<DnsResponse, ProtoError>;
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use core::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicU8, Ordering},
    };

    use test_support::subscribe;
    use tokio::time::sleep;

    use super::*;
    use crate::{
        op::ResponseCode,
        runtime::{TokioRuntimeProvider, TokioTime},
        udp::tests::{
            udp_client_stream_bad_id_test, udp_client_stream_response_limit_test,
            udp_client_stream_test,
        },
    };

    #[tokio::test]
    async fn test_udp_client_stream_ipv4() {
        subscribe();
        udp_client_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), TokioRuntimeProvider::new()).await;
    }

    #[tokio::test]
    async fn test_udp_client_stream_ipv4_bad_id() {
        subscribe();
        udp_client_stream_bad_id_test(IpAddr::V4(Ipv4Addr::LOCALHOST), TokioRuntimeProvider::new())
            .await;
    }

    #[tokio::test]
    async fn test_udp_client_stream_ipv4_resp_limit() {
        subscribe();
        udp_client_stream_response_limit_test(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            TokioRuntimeProvider::new(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_udp_client_stream_ipv6() {
        subscribe();
        udp_client_stream_test(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            TokioRuntimeProvider::new(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_udp_client_stream_ipv6_bad_id() {
        subscribe();
        udp_client_stream_bad_id_test(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            TokioRuntimeProvider::new(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_udp_client_stream_ipv6_resp_limit() {
        subscribe();
        udp_client_stream_response_limit_test(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            TokioRuntimeProvider::new(),
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn retry_handler_test() -> Result<(), std::io::Error> {
        let mut message = Message::query();
        message.set_response_code(ResponseCode::NoError);

        let ret = retry::<TokioRuntimeProvider>(
            FixedResponse {
                response: DnsResponse::from_message(message.clone())?,
            },
            Duration::from_millis(200),
            5,
        )
        .await?;
        assert_eq!(ret.response_code(), ResponseCode::NoError);

        // test: retry timer doesn't fire extra tasks before the retry interval
        let (req, tries) = DelayedResponse::new(
            DnsResponse::from_message(message.clone()).unwrap(),
            Duration::from_millis(100),
            Arc::new(AtomicU8::new(0)),
        );
        retry::<TokioRuntimeProvider>(req, Duration::from_millis(200), 5).await?;
        assert_eq!(tries.load(Ordering::Relaxed), 1);

        // test: retry timer does fire extra tasks after the retry interval
        let (req, tries) = DelayedResponse::new(
            DnsResponse::from_message(message.clone()).unwrap(),
            Duration::from_millis(1500),
            Arc::new(AtomicU8::new(0)),
        );
        retry::<TokioRuntimeProvider>(req, Duration::from_millis(200), 5).await?;
        assert_eq!(tries.load(Ordering::Relaxed), 5);

        // test: retry timer tasks when nested under a Time::timer
        let (req, tries) = DelayedResponse::new(
            DnsResponse::from_message(message.clone()).unwrap(),
            Duration::from_millis(1000),
            Arc::new(AtomicU8::new(0)),
        );
        let timer_ret = TokioTime::timeout(
            Duration::from_millis(500),
            retry::<TokioRuntimeProvider>(req, Duration::from_millis(200), 5),
        )
        .await;

        if let Err(e) = timer_ret {
            assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        } else {
            panic!("timer did not timeout");
        }

        assert_eq!(tries.load(Ordering::Relaxed), 3);

        Ok(())
    }

    struct FixedResponse {
        response: DnsResponse,
    }

    impl Request for FixedResponse {
        async fn send(&self) -> Result<DnsResponse, ProtoError> {
            Ok(self.response.clone())
        }
    }

    struct DelayedResponse {
        response: DnsResponse,
        delay: Duration,
        counter: Arc<AtomicU8>,
    }

    impl DelayedResponse {
        fn new(
            response: DnsResponse,
            delay: Duration,
            counter: Arc<AtomicU8>,
        ) -> (Self, Arc<AtomicU8>) {
            (
                Self {
                    response,
                    delay,
                    counter: counter.clone(),
                },
                counter,
            )
        }
    }

    impl Request for DelayedResponse {
        async fn send(&self) -> Result<DnsResponse, ProtoError> {
            let _ = self.counter.fetch_add(1, Ordering::Relaxed);
            sleep(self.delay).await;
            Ok(self.response.clone())
        }
    }
}
