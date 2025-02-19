// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use futures_util::stream::Stream;
use futures_util::{TryFutureExt, future::Future, ready};
use tracing::{debug, trace, warn};

use crate::runtime::{RuntimeProvider, Time};
use crate::udp::MAX_RECEIVE_BUFFER_SIZE;
use crate::xfer::{BufDnsStreamHandle, SerialMessage, StreamReceiver};

/// Trait for DnsUdpSocket
#[async_trait]
pub trait DnsUdpSocket
where
    Self: Send + Sync + Sized + Unpin,
{
    /// Time implementation used for this type
    type Time: Time;

    /// Poll once Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    /// Poll once to send data to the given address.
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// Send data to the given address.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
}

/// Trait for UdpSocket
#[async_trait]
pub trait UdpSocket: DnsUdpSocket {
    /// setups up a "client" udp connection that will only receive packets from the associated address
    async fn connect(addr: SocketAddr) -> io::Result<Self>;

    /// same as connect, but binds to the specified local address for sending address
    async fn connect_with_bind(addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self>;

    /// a "server" UDP socket, that bind to the local listening address, and unbound remote address (can receive from anything)
    async fn bind(addr: SocketAddr) -> io::Result<Self>;
}

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpStream<P: RuntimeProvider> {
    socket: P::Udp,
    outbound_messages: StreamReceiver,
}

impl<P: RuntimeProvider> UdpStream<P> {
    /// This method is intended for client connections, see [`Self::with_bound`] for a method better
    ///  for straight listening. It is expected that the resolver wrapper will be responsible for
    ///  creating and managing new UdpStreams such that each new client would have a random port
    ///  (reduce chance of cache poisoning). This will return a randomly assigned local port, unless
    ///  a nonzero port number is specified in `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `remote_addr` - socket address for the remote connection (used to determine IPv4 or IPv6)
    /// * `bind_addr` - optional local socket address to connect from (if a nonzero port number is
    ///                 specified, it will be used instead of randomly selecting a port)
    /// * `os_port_selection` - Boolean parameter to specify whether to use the operating system's
    ///                         standard UDP port selection logic instead of Hickory's logic to
    ///                         securely select a random source port. We do not recommend using
    ///                         this option unless absolutely necessary, as the operating system
    ///                         may select ephemeral ports from a smaller range than Hickory, which
    ///                         can make response poisoning attacks easier to conduct. Some
    ///                         operating systems (notably, Windows) might display a user-prompt to
    ///                         allow a Hickory-specified port to be used, and setting this option
    ///                         will prevent those prompts from being displayed. If os_port_selection
    ///                         is true, avoid_local_udp_ports will be ignored.
    /// * `provider` - async runtime provider, for I/O and timers
    ///
    /// # Return
    ///
    /// A tuple of a Future of a Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    #[allow(clippy::type_complexity)]
    pub fn new(
        remote_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        avoid_local_ports: Option<Arc<HashSet<u16>>>,
        os_port_selection: bool,
        provider: P,
    ) -> (
        Box<dyn Future<Output = Result<Self, io::Error>> + Send + Unpin>,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(remote_addr);

        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = NextRandomUdpSocket::new(
            remote_addr,
            bind_addr,
            avoid_local_ports.unwrap_or_default(),
            os_port_selection,
            provider,
        );

        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream = Box::new(next_socket.map_ok(move |socket| Self {
            socket,
            outbound_messages,
        }));

        (stream, message_sender)
    }
}

impl<P: RuntimeProvider> UdpStream<P> {
    /// Initialize the Stream with an already bound socket. Generally this should be only used for
    ///  server listening sockets. See [`Self::new`] for a client oriented socket. Specifically,
    ///  this requires there is already a bound socket, whereas `new` makes sure to randomize ports
    ///  for additional cache poison prevention.
    ///
    /// # Arguments
    ///
    /// * `socket` - an already bound UDP socket
    /// * `remote_addr` - remote side of this connection
    ///
    /// # Return
    ///
    /// A tuple of a Stream which will handle sending and receiving messages, and a handle which can
    ///  be used to send messages into the stream.
    pub fn with_bound(socket: P::Udp, remote_addr: SocketAddr) -> (Self, BufDnsStreamHandle) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(remote_addr);
        let stream = Self {
            socket,
            outbound_messages,
        };

        (stream, message_sender)
    }

    #[allow(unused)]
    pub(crate) fn from_parts(socket: P::Udp, outbound_messages: StreamReceiver) -> Self {
        Self {
            socket,
            outbound_messages,
        }
    }
}

impl<P: RuntimeProvider> UdpStream<P> {
    #[allow(clippy::type_complexity)]
    fn pollable_split(&mut self) -> (&mut P::Udp, &mut StreamReceiver) {
        (&mut self.socket, &mut self.outbound_messages)
    }
}

impl<P: RuntimeProvider> Stream for UdpStream<P> {
    type Item = Result<SerialMessage, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (socket, outbound_messages) = self.pollable_split();
        let socket = Pin::new(socket);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        while let Poll::Ready(Some(message)) = outbound_messages.as_mut().poll_peek(cx) {
            // first try to send
            let addr = message.addr();

            // this will return if not ready,
            //   meaning that sending will be preferred over receiving...

            // TODO: shouldn't this return the error to send to the sender?
            if let Err(e) = ready!(socket.poll_send_to(cx, message.bytes(), addr)) {
                // Drop the UDP packet and continue
                warn!(
                    "error sending message to {} on udp_socket, dropping response: {}",
                    addr, e
                );
            }

            // message sent, need to pop the message
            assert!(outbound_messages.as_mut().poll_next(cx).is_ready());
        }

        // For QoS, this will only accept one message and output that
        // receive all inbound messages

        // TODO: this should match edns settings
        let mut buf = [0u8; MAX_RECEIVE_BUFFER_SIZE];
        let (len, src) = ready!(socket.poll_recv_from(cx, &mut buf))?;

        let serial_message = SerialMessage::new(buf.iter().take(len).cloned().collect(), src);
        Poll::Ready(Some(Ok(serial_message)))
    }
}

#[must_use = "futures do nothing unless polled"]
pub(crate) struct NextRandomUdpSocket<P: RuntimeProvider> {
    name_server: SocketAddr,
    bind_address: SocketAddr,
    provider: P,
    /// Number of unsuccessful attempts to pick a port.
    attempted: usize,
    #[allow(clippy::type_complexity)]
    future: Option<Pin<Box<dyn Send + Future<Output = io::Result<P::Udp>>>>>,
    avoid_local_ports: Arc<HashSet<u16>>,
    os_port_selection: bool,
}

impl<P: RuntimeProvider> NextRandomUdpSocket<P> {
    /// Creates a future for randomly binding to a local socket address for client connections,
    /// if no port is specified.
    ///
    /// If a port is specified in the bind address it is used.
    pub(crate) fn new(
        name_server: SocketAddr,
        bind_addr: Option<SocketAddr>,
        avoid_local_ports: Arc<HashSet<u16>>,
        os_port_selection: bool,
        provider: P,
    ) -> Self {
        let bind_address = match bind_addr {
            Some(ba) => ba,
            None => match name_server {
                SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            },
        };

        Self {
            name_server,
            bind_address,
            provider,
            attempted: 0,
            future: None,
            avoid_local_ports,
            os_port_selection,
        }
    }
}

impl<P: RuntimeProvider> Future for NextRandomUdpSocket<P> {
    type Output = Result<P::Udp, io::Error>;

    /// polls until there is an available next random UDP port,
    /// if no port has been specified in bind_addr.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            this.future = match this.future.take() {
                Some(mut future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(socket)) => {
                        debug!("created socket successfully");
                        return Poll::Ready(Ok(socket));
                    }
                    Poll::Ready(Err(err)) => match err.kind() {
                        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
                            if this.attempted < ATTEMPT_RANDOM + 1 =>
                        {
                            debug!("unable to bind port, attempt: {}: {err}", this.attempted);
                            this.attempted += 1;
                            None
                        }
                        _ => {
                            debug!("failed to bind port: {}", err);
                            return Poll::Ready(Err(err));
                        }
                    },
                    Poll::Pending => {
                        debug!("unable to bind port, attempt: {}", this.attempted);
                        this.future = Some(future);
                        return Poll::Pending;
                    }
                },
                None => {
                    let mut bind_addr = this.bind_address;

                    if !this.os_port_selection && bind_addr.port() == 0 {
                        while this.attempted < ATTEMPT_RANDOM {
                            // Per RFC 6056 Section 3.2:
                            //
                            // As mentioned in Section 2.1, the dynamic ports consist of the range
                            // 49152-65535.  However, ephemeral port selection algorithms should use
                            // the whole range 1024-65535.
                            let port = rand::random_range(1024..=u16::MAX);
                            if this.avoid_local_ports.contains(&port) {
                                // Count this against the total number of attempts to pick a port.
                                // RFC 6056 Section 3.3.2 notes that this algorithm should find a
                                // suitable port in one or two attempts with high probability in
                                // common scenarios. If `avoid_local_ports` is pathologically large,
                                // then incrementing the counter here will prevent an infinite loop.
                                this.attempted += 1;
                                continue;
                            } else {
                                bind_addr = SocketAddr::new(bind_addr.ip(), port);
                                break;
                            }
                        }
                    }

                    trace!(port = bind_addr.port(), "binding UDP socket");
                    Some(Box::pin(
                        this.provider.bind_udp(bind_addr, this.name_server),
                    ))
                }
            }
        }
    }
}

const ATTEMPT_RANDOM: usize = 10;

#[cfg(feature = "tokio")]
#[async_trait]
impl UdpSocket for tokio::net::UdpSocket {
    /// sets up up a "client" udp connection that will only receive packets from the associated address
    ///
    /// if the addr is ipv4 then it will bind local addr to 0.0.0.0:0, ipv6 \[::\]0
    async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = match addr {
            SocketAddr::V4(_addr) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_addr) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };

        Self::connect_with_bind(addr, bind_addr).await
    }

    /// same as connect, but binds to the specified local address for sending address
    async fn connect_with_bind(_addr: SocketAddr, bind_addr: SocketAddr) -> io::Result<Self> {
        let socket = Self::bind(bind_addr).await?;

        // TODO: research connect more, it appears to break UDP receiving tests, etc...
        // socket.connect(addr).await?;

        Ok(socket)
    }

    async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Self::bind(addr).await
    }
}

#[cfg(feature = "tokio")]
#[async_trait]
impl DnsUdpSocket for tokio::net::UdpSocket {
    type Time = crate::runtime::TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        let addr = ready!(Self::poll_recv_from(self, cx, &mut buf))?;
        let len = buf.filled().len();

        Poll::Ready(Ok((len, addr)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        Self::poll_send_to(self, cx, buf, target)
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use test_support::subscribe;

    use crate::{
        runtime::TokioRuntimeProvider,
        tests::{next_random_socket_test, udp_stream_test},
    };

    #[tokio::test]
    async fn test_next_random_socket() {
        subscribe();
        let provider = TokioRuntimeProvider::new();
        next_random_socket_test(provider).await;
    }

    #[tokio::test]
    async fn test_udp_stream_ipv4() {
        subscribe();
        let provider = TokioRuntimeProvider::new();
        udp_stream_test(IpAddr::V4(Ipv4Addr::LOCALHOST), provider).await;
    }

    #[tokio::test]
    async fn test_udp_stream_ipv6() {
        subscribe();
        let provider = TokioRuntimeProvider::new();
        udp_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), provider).await;
    }
}
