// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{future::Future, stream::Stream};
use tracing::{debug, trace, warn};

use crate::error::ProtoError;
use crate::op::{Message, MessageFinalizer, MessageVerifier};
use crate::runtime::{RuntimeProvider, Time};
use crate::udp::udp_stream::NextRandomUdpSocket;
use crate::udp::{DnsUdpSocket, MAX_RECEIVE_BUFFER_SIZE};
use crate::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream, SerialMessage};

/// A builder to create a UDP client stream.
///
/// This is created by [`UdpClientStream::builder`].
pub struct UdpClientStreamBuilder<P> {
    name_server: SocketAddr,
    timeout: Option<Duration>,
    signer: Option<Arc<dyn MessageFinalizer>>,
    bind_addr: Option<SocketAddr>,
    avoid_local_ports: Arc<HashSet<u16>>,
    provider: P,
}

impl<P> UdpClientStreamBuilder<P> {
    /// Sets the connection timeout.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the message finalizer to be applied to queries.
    pub fn with_signer(self, signer: Option<Arc<dyn MessageFinalizer>>) -> Self {
        Self {
            name_server: self.name_server,
            timeout: self.timeout,
            signer,
            bind_addr: self.bind_addr,
            avoid_local_ports: self.avoid_local_ports,
            provider: self.provider,
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
            provider: self.provider,
        }
    }
}

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
    signer: Option<Arc<dyn MessageFinalizer>>,
    bind_addr: Option<SocketAddr>,
    avoid_local_ports: Arc<HashSet<u16>>,
    provider: P,
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
            provider,
        }
    }
}

impl<P> Display for UdpClientStream<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "UDP({})", self.name_server)
    }
}

/// creates random query_id, each socket is unique, no need for global uniqueness
fn random_query_id() -> u16 {
    use rand::distributions::{Distribution, Standard};
    let mut rand = rand::thread_rng();

    Standard.sample(&mut rand)
}

impl<P: RuntimeProvider> DnsRequestSender for UdpClientStream<P> {
    fn send_message(&mut self, mut message: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // associated the ID for this request, b/c this connection is unique to socket port, the ID
        //   does not need to be globally unique
        message.set_id(random_query_id());

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => now.as_secs(),
            Err(_) => return ProtoError::from("Current time is before the Unix epoch.").into(),
        };

        // TODO: truncates u64 to u32, error on overflow?
        let now = now as u32;

        let mut verifier = None;
        if let Some(signer) = &self.signer {
            if signer.should_finalize_message(&message) {
                match message.finalize(&**signer, now) {
                    Ok(answer_verifier) => verifier = answer_verifier,
                    Err(e) => {
                        debug!("could not sign message: {}", e);
                        return e.into();
                    }
                }
            }
        }

        // Get an appropriate read buffer size.
        let recv_buf_size = MAX_RECEIVE_BUFFER_SIZE.min(message.max_payload() as usize);

        let bytes = match message.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => {
                return err.into();
            }
        };

        let message_id = message.id();
        let message = SerialMessage::new(bytes, self.name_server);

        debug!(
            "final message: {}",
            message
                .to_message()
                .expect("bizarre we just made this message")
        );
        let provider = self.provider.clone();
        let addr = message.addr();
        let bind_addr = self.bind_addr;
        let avoid_local_ports = self.avoid_local_ports.clone();

        P::Timer::timeout::<Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>>(
            self.timeout,
            Box::pin(async move {
                let socket =
                    NextRandomUdpSocket::new(addr, bind_addr, avoid_local_ports, provider).await?;
                send_serial_message_inner(message, message_id, verifier, socket, recv_buf_size)
                    .await
            }),
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

/// A future that resolves to an UdpClientStream
pub struct UdpClientConnect<P> {
    name_server: SocketAddr,
    timeout: Duration,
    signer: Option<Arc<dyn MessageFinalizer>>,
    bind_addr: Option<SocketAddr>,
    avoid_local_ports: Arc<HashSet<u16>>,
    provider: P,
}

impl<P: RuntimeProvider> Future for UdpClientConnect<P> {
    type Output = Result<UdpClientStream<P>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: this doesn't need to be a future?
        Poll::Ready(Ok(UdpClientStream {
            name_server: self.name_server,
            is_shutdown: false,
            timeout: self.timeout,
            signer: self.signer.take(),
            bind_addr: self.bind_addr,
            avoid_local_ports: self.avoid_local_ports.clone(),
            provider: self.provider.clone(),
        }))
    }
}

async fn send_serial_message_inner<S: DnsUdpSocket + Send>(
    msg: SerialMessage,
    msg_id: u16,
    verifier: Option<MessageVerifier>,
    socket: S,
    recv_buf_size: usize,
) -> Result<DnsResponse, ProtoError> {
    let bytes = msg.bytes();
    let addr = msg.addr();
    let len_sent: usize = socket.send_to(bytes, addr).await?;

    if bytes.len() != len_sent {
        return Err(ProtoError::from(format!(
            "Not all bytes of message sent, {} of {}",
            len_sent,
            bytes.len()
        )));
    }

    // Create the receive buffer.
    trace!("creating UDP receive buffer with size {recv_buf_size}");
    let mut recv_buf = vec![0; recv_buf_size];

    // TODO: limit the max number of attempted messages? this relies on a timeout to die...
    loop {
        let (len, src) = socket.recv_from(&mut recv_buf).await?;

        // Copy the slice of read bytes.
        let response_bytes = &recv_buf[0..len];
        let response_buffer = Vec::from(response_bytes);

        // compare expected src to received packet
        let request_target = msg.addr();

        // Comparing the IP and Port directly as internal information about the link is stored with the IpAddr, see https://github.com/hickory-dns/hickory-dns/issues/2081
        if src.ip() != request_target.ip() || src.port() != request_target.port() {
            warn!(
                "ignoring response from {} because it does not match name_server: {}.",
                src, request_target,
            );

            // await an answer from the correct NameServer
            continue;
        }

        match DnsResponse::from_buffer(response_buffer) {
            Ok(response) => {
                // Validate the message id in the response matches the value chosen for the query.
                if msg_id != response.id() {
                    // on wrong id, attempted poison?
                    warn!(
                        "expected message id: {} got: {}, dropped",
                        msg_id,
                        response.id()
                    );

                    continue;
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
                let response_queries = response.queries();

                if !response_queries
                    .iter()
                    .all(|elem| request_queries.contains(elem))
                {
                    warn!("detected forged question section: we expected '{request_queries:?}', but received '{response_queries:?}' from server {src}");
                    continue;
                }

                debug!("received message id: {}", response.id());
                if let Some(mut verifier) = verifier {
                    return verifier(response_bytes);
                } else {
                    return Ok(response);
                }
            }
            Err(e) => {
                // on errors deserializing, continue
                warn!(
                    "dropped malformed message waiting for id: {} err: {}",
                    msg_id, e
                );

                continue;
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]
    use crate::{runtime::TokioRuntimeProvider, tests::udp_client_stream_test};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use test_support::subscribe;
    use tokio::runtime::Runtime;

    #[test]
    fn test_udp_client_stream_ipv4() {
        subscribe();
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        let provider = TokioRuntimeProvider::new();
        udp_client_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), io_loop, provider)
    }

    #[test]
    fn test_udp_client_stream_ipv6() {
        subscribe();
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        let provider = TokioRuntimeProvider::new();
        udp_client_stream_test(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            io_loop,
            provider,
        )
    }
}
