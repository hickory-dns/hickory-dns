// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::stream::Stream;
use futures_util::{future::Future, ready, TryFutureExt};
use log::debug;
use rand;
use rand::distributions::{uniform::Uniform, Distribution};

use crate::xfer::{BufStreamHandle, SerialMessage, StreamReceiver};
use crate::Time;

/// Trait for UdpSocket
#[async_trait]
pub trait UdpSocket
where
    Self: Send + Sync + Sized + Unpin,
{
    /// Time implementation used for this type
    type Time: Time;

    /// UdpSocket
    async fn bind(addr: SocketAddr) -> io::Result<Self>;

    /// Poll once Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        futures_util::future::poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    /// Poll once to send data to the given address.
    fn poll_send_to(
        &self,
        cx: &mut Context,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// Send data to the given address.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        futures_util::future::poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }
}

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpStream<S: Send> {
    socket: S,
    outbound_messages: StreamReceiver,
}

impl<S: UdpSocket + Send + 'static> UdpStream<S> {
    /// This method is intended for client connections, see `with_bound` for a method better for
    ///  straight listening. It is expected that the resolver wrapper will be responsible for
    ///  creating and managing new UdpStreams such that each new client would have a random port
    ///  (reduce chance of cache poisoning). This will return a randomly assigned local port.
    ///
    /// # Arguments
    ///
    /// * `name_server` - socket address for the remote server (used to determine IPv4 or IPv6)
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    #[allow(clippy::type_complexity)]
    pub fn new(
        name_server: SocketAddr,
    ) -> (
        Box<dyn Future<Output = Result<UdpStream<S>, io::Error>> + Send + Unpin>,
        BufStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufStreamHandle::create();

        // TODO: allow the bind address to be specified...
        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = NextRandomUdpSocket::new(&name_server);

        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream = Box::new(next_socket.map_ok(move |socket| UdpStream {
            socket,
            outbound_messages,
        }));

        (stream, message_sender)
    }

    /// Initialize the Stream with an already bound socket. Generally this should be only used for
    ///  server listening sockets. See `new` for a client oriented socket. Specifically, this there
    ///  is already a bound socket in this context, whereas `new` makes sure to randomize ports
    ///  for additional cache poison prevention.
    ///
    /// # Arguments
    ///
    /// * `socket` - an already bound UDP socket
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messsages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn with_bound(socket: S) -> (Self, BufStreamHandle) {
        let (message_sender, outbound_messages) = BufStreamHandle::create();
        let stream = UdpStream {
            socket,
            outbound_messages,
        };

        (stream, message_sender)
    }

    #[allow(unused)]
    pub(crate) fn from_parts(socket: S, outbound_messages: StreamReceiver) -> Self {
        UdpStream {
            socket,
            outbound_messages,
        }
    }
}

impl<S: Send> UdpStream<S> {
    #[allow(clippy::type_complexity)]
    fn pollable_split(&mut self) -> (&mut S, &mut StreamReceiver) {
        (&mut self.socket, &mut self.outbound_messages)
    }
}

impl<S: UdpSocket + Send + 'static> Stream for UdpStream<S> {
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

            // this wiil return if not ready,
            //   meaning that sending will be prefered over receiving...

            // TODO: shouldn't this return the error to send to the sender?
            ready!(socket.poll_send_to(cx, message.bytes(), addr))?;

            // message sent, need to pop the message
            assert!(outbound_messages.as_mut().poll_next(cx).is_ready());
        }

        // For QoS, this will only accept one message and output that
        // receive all inbound messages

        // TODO: this should match edns settings
        let mut buf = [0u8; 4096];
        let (len, src) = ready!(socket.poll_recv_from(cx, &mut buf))?;

        let serial_message = SerialMessage::new(buf.iter().take(len).cloned().collect(), src);
        Poll::Ready(Some(Ok(serial_message)))
    }
}

#[must_use = "futures do nothing unless polled"]
pub(crate) struct NextRandomUdpSocket<S> {
    bind_address: IpAddr,
    marker: PhantomData<S>,
}

impl<S: UdpSocket> NextRandomUdpSocket<S> {
    /// Creates a future for randomly binding to a local socket address for client connections.
    pub(crate) fn new(name_server: &SocketAddr) -> NextRandomUdpSocket<S> {
        let zero_addr: IpAddr = match *name_server {
            SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        };

        NextRandomUdpSocket {
            bind_address: zero_addr,
            marker: PhantomData,
        }
    }

    async fn bind(zero_addr: SocketAddr) -> Result<S, io::Error> {
        S::bind(zero_addr).await
    }
}

impl<S: UdpSocket> Future for NextRandomUdpSocket<S> {
    type Output = Result<S, io::Error>;

    /// polls until there is an available next random UDP port.
    ///
    /// if there is no port available after 10 attempts, returns NotReady
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let rand_port_range = Uniform::new_inclusive(1025_u16, u16::max_value());
        let mut rand = rand::thread_rng();

        for attempt in 0..10 {
            let port = rand_port_range.sample(&mut rand); // the range is [0 ... u16::max]
            let zero_addr = SocketAddr::new(self.bind_address, port);

            // TODO: allow TTL to be adjusted...
            // TODO: this immediate poll might be wrong in some cases...
            match Box::pin(Self::bind(zero_addr)).as_mut().poll(cx) {
                Poll::Ready(Ok(socket)) => {
                    debug!("created socket successfully");
                    return Poll::Ready(Ok(socket));
                }
                Poll::Ready(Err(err)) => {
                    debug!("unable to bind port, attempt: {}: {}", attempt, err)
                }
                Poll::Pending => debug!("unable to bind port, attempt: {}", attempt),
            }
        }

        debug!("could not get next random port, delaying");

        // TODO: because no interest is registered anywhere, we must awake.
        cx.waker().wake_by_ref();

        // returning NotReady here, perhaps the next poll there will be some more socket available.
        Poll::Pending
    }
}

#[cfg(feature = "tokio-runtime")]
#[async_trait]
impl UdpSocket for tokio::net::UdpSocket {
    type Time = crate::TokioTime;

    async fn bind(addr: SocketAddr) -> io::Result<Self> {
        tokio::net::UdpSocket::bind(addr).await
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        let addr = ready!(tokio::net::UdpSocket::poll_recv_from(self, cx, &mut buf))?;
        let len = buf.filled().len();

        Poll::Ready(Ok((len, addr)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        tokio::net::UdpSocket::poll_send_to(self, cx, buf, target)
    }
}

#[cfg(test)]
#[cfg(feature = "tokio-runtime")]
mod tests {
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    use std::net::Ipv6Addr;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::{net::UdpSocket as TokioUdpSocket, runtime::Runtime};

    #[test]
    fn test_next_random_socket() {
        use crate::tests::next_random_socket_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        next_random_socket_test::<TokioUdpSocket, Runtime>(io_loop)
    }

    #[test]
    fn test_udp_stream_ipv4() {
        use crate::tests::udp_stream_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        io_loop.block_on(udp_stream_test::<TokioUdpSocket>(IpAddr::V4(
            Ipv4Addr::new(127, 0, 0, 1),
        )));
    }

    #[test]
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    fn test_udp_stream_ipv6() {
        use crate::tests::udp_stream_test;
        let io_loop = Runtime::new().expect("failed to create tokio runtime");
        io_loop.block_on(udp_stream_test::<TokioUdpSocket>(IpAddr::V6(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        )));
    }
}
