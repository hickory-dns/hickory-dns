// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::borrow::Borrow;
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{future::Future, stream::Stream};
use tracing::{debug, warn};

use crate::error::ProtoError;
use crate::op::message::NoopMessageFinalizer;
use crate::op::{MessageFinalizer, MessageVerifier};
use crate::udp::udp_stream::{NextRandomUdpSocket, UdpSocket};
use crate::xfer::{DnsRequest, DnsRequestSender, DnsResponse, DnsResponseStream, SerialMessage};
use crate::Time;

/// A UDP client stream of DNS binary packets
///
/// This stream will create a new UDP socket for every request. This is to avoid potential cache
///   poisoning during use by UDP based attacks.
#[must_use = "futures do nothing unless polled"]
pub struct UdpClientStream<S, MF = NoopMessageFinalizer>
where
    S: Send,
    MF: MessageFinalizer,
{
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    timeout: Duration,
    is_shutdown: bool,
    signer: Option<Arc<MF>>,
    marker: PhantomData<S>,
}

impl<S: Send> UdpClientStream<S, NoopMessageFinalizer> {
    /// it is expected that the resolver wrapper will be responsible for creating and managing
    ///  new UdpClients such that each new client would have a random port (reduce chance of cache
    ///  poisoning)
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(name_server: SocketAddr) -> UdpClientConnect<S, NoopMessageFinalizer> {
        Self::with_timeout(name_server, Duration::from_secs(5))
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
    ) -> UdpClientConnect<S, NoopMessageFinalizer> {
        Self::with_bind_addr_and_timeout(name_server, None, timeout)
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
    ) -> UdpClientConnect<S, NoopMessageFinalizer> {
        Self::with_timeout_and_signer_and_bind_addr(name_server, timeout, None, bind_addr)
    }
}

impl<S: Send, MF: MessageFinalizer> UdpClientStream<S, MF> {
    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_timeout_and_signer(
        name_server: SocketAddr,
        timeout: Duration,
        signer: Option<Arc<MF>>,
    ) -> UdpClientConnect<S, MF> {
        UdpClientConnect {
            name_server,
            bind_addr: None,
            timeout,
            signer,
            marker: PhantomData::<S>,
        }
    }

    /// Constructs a new TcpStream for a client to the specified SocketAddr.
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
    ) -> UdpClientConnect<S, MF> {
        UdpClientConnect {
            name_server,
            bind_addr,
            timeout,
            signer,
            marker: PhantomData::<S>,
        }
    }
}

impl<S: Send, MF: MessageFinalizer> Display for UdpClientStream<S, MF> {
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

impl<S: UdpSocket + Send + 'static, MF: MessageFinalizer> DnsRequestSender
    for UdpClientStream<S, MF>
{
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

        let bytes = match message.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => {
                return err.into();
            }
        };

        let message_id = message.id();
        let message = SerialMessage::new(bytes, self.name_server);
        let bind_addr = self.bind_addr;

        debug!(
            "final message: {}",
            message
                .to_message()
                .expect("bizarre we just made this message")
        );

        S::Time::timeout::<Pin<Box<dyn Future<Output = Result<DnsResponse, ProtoError>> + Send>>>(
            self.timeout,
            Box::pin(send_serial_message::<S>(
                message, message_id, verifier, bind_addr,
            )),
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
impl<S: Send, MF: MessageFinalizer> Stream for UdpClientStream<S, MF> {
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
pub struct UdpClientConnect<S, MF = NoopMessageFinalizer>
where
    S: Send,
    MF: MessageFinalizer,
{
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    timeout: Duration,
    signer: Option<Arc<MF>>,
    marker: PhantomData<S>,
}

impl<S: Send + Unpin, MF: MessageFinalizer> Future for UdpClientConnect<S, MF> {
    type Output = Result<UdpClientStream<S, MF>, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: this doesn't need to be a future?
        Poll::Ready(Ok(UdpClientStream::<S, MF> {
            name_server: self.name_server,
            bind_addr: self.bind_addr,
            is_shutdown: false,
            timeout: self.timeout,
            signer: self.signer.take(),
            marker: PhantomData,
        }))
    }
}

async fn send_serial_message<S: UdpSocket + Send>(
    msg: SerialMessage,
    msg_id: u16,
    verifier: Option<MessageVerifier>,
    bind_addr: Option<SocketAddr>,
) -> Result<DnsResponse, ProtoError> {
    let name_server = msg.addr();
    let socket: S = NextRandomUdpSocket::new(&name_server, &bind_addr).await?;
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

    // TODO: limit the max number of attempted messages? this relies on a timeout to die...
    loop {
        // TODO: consider making this heap based? need to verify it matches EDNS settings
        let mut recv_buf = [0u8; 2048];

        let (len, src) = socket.recv_from(&mut recv_buf).await?;
        let response = SerialMessage::new(recv_buf.iter().take(len).cloned().collect(), src);

        // compare expected src to received packet
        let request_target = msg.addr();

        if response.addr() != request_target {
            warn!(
                "ignoring response from {} because it does not match name_server: {}.",
                response.addr(),
                request_target,
            );

            // await an answer from the correct NameServer
            continue;
        }

        // TODO: match query strings from request and response?

        match response.to_message() {
            Ok(message) => {
                if msg_id == message.id() {
                    debug!("received message id: {}", message.id());
                    if let Some(mut verifier) = verifier {
                        return verifier(response.bytes());
                    } else {
                        return Ok(DnsResponse::from(message));
                    }
                } else {
                    // on wrong id, attempted poison?
                    warn!(
                        "expected message id: {} got: {}, dropped",
                        msg_id,
                        message.id()
                    );

                    continue;
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
    use crate::tests::udp_client_stream_test;
    use crate::TokioTime;
    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv6Addr;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::{net::UdpSocket as TokioUdpSocket, runtime::Runtime};

    #[test]
    fn test_udp_client_stream_ipv4() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        udp_client_stream_test::<TokioUdpSocket, Runtime, TokioTime>(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            io_loop,
        )
    }

    #[test]
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    fn test_udp_client_stream_ipv6() {
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        udp_client_stream_test::<TokioUdpSocket, Runtime, TokioTime>(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            io_loop,
        )
    }
}
