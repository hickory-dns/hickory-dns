// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::sync::Arc;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::borrow::Borrow;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloc::boxed::Box;
use alloc::vec::Vec;
use futures_util::{future::Future, stream::Stream};
use tracing::{debug, trace, warn};

use crate::error::ProtoError;
use crate::op::message::NoopMessageFinalizer;
use crate::op::{Message, MessageFinalizer, MessageVerifier};
use crate::runtime::RuntimeProvider;
use crate::runtime::Time;
use crate::udp::udp_stream::NextRandomUdpSocket;
use crate::udp::{DnsUdpSocket, MAX_RECEIVE_BUFFER_SIZE};
use crate::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream, SerialMessage};

/// A UDP client stream of DNS binary packets
///
/// This stream will create a new UDP socket for every request. This is to avoid potential cache
///   poisoning during use by UDP based attacks.
#[must_use = "futures do nothing unless polled"]
pub struct UdpClientStream<P, MF = NoopMessageFinalizer>
where
    MF: MessageFinalizer,
{
    name_server: SocketAddr,
    timeout: Duration,
    is_shutdown: bool,
    signer: Option<Arc<MF>>,
    bind_addr: Option<SocketAddr>,
    provider: P,
}

impl<P: RuntimeProvider> UdpClientStream<P, NoopMessageFinalizer> {
    /// it is expected that the resolver wrapper will be responsible for creating and managing
    ///  new UdpClients such that each new client would have a random port (reduce chance of cache
    ///  poisoning)
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(name_server: SocketAddr, provider: P) -> UdpClientConnect<P> {
        Self::with_timeout(name_server, Duration::from_secs(5), provider)
    }

    /// Constructs a new UdpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
        provider: P,
    ) -> UdpClientConnect<P> {
        Self::with_bind_addr_and_timeout(name_server, None, timeout, provider)
    }

    /// Constructs a new UdpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `bind_addr` - the IP and port to connect from
    /// * `timeout` - connection timeout
    pub fn with_bind_addr_and_timeout(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Duration,
        provider: P,
    ) -> UdpClientConnect<P> {
        Self::with_timeout_and_signer_and_bind_addr(name_server, timeout, None, bind_addr, provider)
    }
}

impl<P: RuntimeProvider, MF: MessageFinalizer> UdpClientStream<P, MF> {
    /// Constructs a new UdpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_timeout_and_signer(
        name_server: SocketAddr,
        timeout: Duration,
        signer: Option<Arc<MF>>,
        provider: P,
    ) -> UdpClientConnect<P, MF> {
        UdpClientConnect {
            name_server,
            timeout,
            signer,
            bind_addr: None,
            provider,
        }
    }

    /// Constructs a new UdpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    /// * `bind_addr` - the IP address and port to connect from
    pub fn with_timeout_and_signer_and_bind_addr(
        name_server: SocketAddr,
        timeout: Duration,
        signer: Option<Arc<MF>>,
        bind_addr: Option<SocketAddr>,
        provider: P,
    ) -> UdpClientConnect<P, MF> {
        UdpClientConnect {
            name_server,
            timeout,
            signer,
            bind_addr,
            provider,
        }
    }
}

impl<P: RuntimeProvider, MF: MessageFinalizer> UdpClientStream<P, MF> {
    /// Constructs a new UdpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `signer` - optional final amendment
    /// * `timeout` - connection timeout
    /// * `creator` - function that binds a local address to a newly created UDP socket
    pub fn with_provider(
        name_server: SocketAddr,
        signer: Option<Arc<MF>>,
        timeout: Duration,
        provider: P,
    ) -> UdpClientConnect<P, MF> {
        UdpClientConnect {
            name_server,
            timeout,
            signer,
            bind_addr: None,
            provider,
        }
    }
}

impl<P, MF: MessageFinalizer> Display for UdpClientStream<P, MF> {
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

impl<P: RuntimeProvider, MF: MessageFinalizer> DnsRequestSender for UdpClientStream<P, MF> {
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
        if let Some(ref signer) = self.signer {
            if signer.should_finalize_message(&message) {
                match message.finalize::<MF>(signer.borrow(), now) {
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

        P::Timer::timeout::<Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>>(
            self.timeout,
            Box::pin(async move {
                let socket = NextRandomUdpSocket::new(addr, bind_addr, provider).await?;
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
impl<P, MF: MessageFinalizer> Stream for UdpClientStream<P, MF> {
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
pub struct UdpClientConnect<P, MF = NoopMessageFinalizer>
where
    MF: MessageFinalizer,
{
    name_server: SocketAddr,
    timeout: Duration,
    signer: Option<Arc<MF>>,
    bind_addr: Option<SocketAddr>,
    provider: P,
}

impl<P: RuntimeProvider, MF: MessageFinalizer> Future for UdpClientConnect<P, MF> {
    type Output = Result<UdpClientStream<P, MF>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: this doesn't need to be a future?
        Poll::Ready(Ok(UdpClientStream {
            name_server: self.name_server,
            is_shutdown: false,
            timeout: self.timeout,
            signer: self.signer.take(),
            bind_addr: self.bind_addr,
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
        let buffer: Vec<_> = Vec::from(&recv_buf[0..len]);

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

        match Message::from_vec(&buffer) {
            Ok(message) => {
                // Validate the message id in the response matches the value chosen for the query.
                if msg_id != message.id() {
                    // on wrong id, attempted poison?
                    warn!(
                        "expected message id: {} got: {}, dropped",
                        msg_id,
                        message.id()
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
                let response_queries = message.queries();

                if !response_queries
                    .iter()
                    .all(|elem| request_queries.contains(elem))
                {
                    warn!("detected forged question section: we expected '{request_queries:?}', but received '{response_queries:?}' from server {src}");
                    continue;
                }

                debug!("received message id: {}", message.id());
                if let Some(mut verifier) = verifier {
                    return verifier(&buffer);
                } else {
                    return Ok(DnsResponse::new(message, buffer));
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
        udp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), io_loop, provider)
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
