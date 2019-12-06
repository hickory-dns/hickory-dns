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
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::stream::{Fuse, Peekable, Stream, StreamExt};
use futures::{ready, Future, FutureExt, TryFutureExt};
use log::debug;
use rand;
use rand::distributions::{uniform::Uniform, Distribution};

use crate::xfer::{BufStreamHandle, SerialMessage};

/// Trait for UdpSocket
#[async_trait]
pub trait UdpSocket
where
    Self: Sized + Unpin,
{
    /// UdpSocket
    async fn bind(addr: &SocketAddr) -> io::Result<Self>;
    /// Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    /// Send data to the given address.
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize>;
}

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpStream<S: Send> {
    socket: S,
    outbound_messages: Peekable<Fuse<UnboundedReceiver<SerialMessage>>>,
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
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        // TODO: allow the bind address to be specified...
        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = NextRandomUdpSocket::new(&name_server);

        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream = Box::new(next_socket.map_ok(move |socket| UdpStream {
            socket,
            outbound_messages: outbound_messages.fuse().peekable(),
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
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        let stream = UdpStream {
            socket,
            outbound_messages: outbound_messages.fuse().peekable(),
        };

        (stream, message_sender)
    }

    #[allow(unused)]
    pub(crate) fn from_parts(
        socket: S,
        outbound_messages: UnboundedReceiver<SerialMessage>,
    ) -> Self {
        UdpStream {
            socket,
            outbound_messages: outbound_messages.fuse().peekable(),
        }
    }
}

impl<S: Send> UdpStream<S> {
    #[allow(clippy::type_complexity)]
    fn pollable_split(
        &mut self,
    ) -> (
        &mut S,
        &mut Peekable<Fuse<UnboundedReceiver<SerialMessage>>>,
    ) {
        (&mut self.socket, &mut self.outbound_messages)
    }
}

impl<S: UdpSocket + Send + 'static> Stream for UdpStream<S> {
    type Item = Result<SerialMessage, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let (socket, outbound_messages) = self.pollable_split();
        let mut socket = Pin::new(socket);
        let mut outbound_messages = Pin::new(outbound_messages);

        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        loop {
            // first try to send
            match outbound_messages.as_mut().poll_peek(cx) {
                Poll::Ready(Some(message)) => {
                    let addr = &message.addr();

                    // this wiil return if not ready,
                    //   meaning that sending will be prefered over receiving...

                    // TODO: shouldn't this return the error to send to the sender?
                    ready!(socket.send_to(message.bytes(), addr).poll_unpin(cx))?;
                }
                // now we get to drop through to the receives...
                // TODO: should we also return None if there are no more messages to send?
                Poll::Pending | Poll::Ready(None) => break,
            }

            // message sent, need to pop the message
            assert!(outbound_messages.as_mut().poll_next(cx).is_ready());
        }

        // For QoS, this will only accept one message and output that
        // receive all inbound messages

        // TODO: this should match edns settings
        let mut buf = [0u8; 2048];
        let (len, src) = ready!(socket.recv_from(&mut buf).poll_unpin(cx))?;

        Poll::Ready(Some(Ok(SerialMessage::new(
            buf.iter().take(len).cloned().collect(),
            src,
        ))))
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
        S::bind(&zero_addr).await
    }
}

impl<S: UdpSocket> Future for NextRandomUdpSocket<S> {
    type Output = Result<S, io::Error>;

    /// polls until there is an available next random UDP port.
    ///
    /// if there is no port available after 10 attempts, returns NotReady
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
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

        // FIXME: this replaced task::current().notify();
        cx.waker().wake_by_ref();

        // returning NotReady here, perhaps the next poll there will be some more socket available.
        Poll::Pending
    }
}

#[test]
fn test_next_random_socket() {
    use tokio::{self, runtime};

    let mut io_loop = runtime::Runtime::new().unwrap();
    let (stream, _) = UdpStream::<tokio::net::UdpSocket>::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        52,
    ));
    drop(
        io_loop
            .block_on(stream)
            .expect("failed to get next socket address"),
    );
}

#[test]
fn test_udp_stream_ipv4() {
    udp_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_udp_stream_ipv6() {
    udp_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}
#[cfg(feature = "tokio-compat")]
use tokio::net;

#[cfg(feature = "tokio-compat")]
#[async_trait]
impl UdpSocket for net::UdpSocket {
    async fn bind(addr: &SocketAddr) -> io::Result<Self> {
        net::UdpSocket::bind(addr).await
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        self.send_to(buf, target).await
    }
}

#[cfg(test)]
fn udp_stream_test(server_addr: IpAddr) {
    use tokio::runtime;

    use std::net::ToSocketAddrs;
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let server = std::net::UdpSocket::bind(SocketAddr::new(server_addr, 0)).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should receive something within 5 seconds...
    server
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should receive something within 5 seconds...
    let server_addr = server.local_addr().unwrap();

    let test_bytes: &'static [u8; 8] = b"DEADBEEF";
    let send_recv_times = 4;

    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name("test_udp_stream_ipv4:server".to_string())
        .spawn(move || {
            let mut buffer = [0_u8; 512];

            for _ in 0..send_recv_times {
                // wait for some bytes...
                let (len, addr) = server.recv_from(&mut buffer).expect("receive failed");

                assert_eq!(&buffer[0..len], test_bytes);

                // bounce them right back...
                assert_eq!(
                    server.send_to(&buffer[0..len], addr).expect("send failed"),
                    len
                );
            }
        })
        .unwrap();

    // setup the client, which is going to run on the testing thread...
    let mut io_loop = runtime::Runtime::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    let client_addr = match server_addr {
        std::net::SocketAddr::V4(_) => "127.0.0.1:0",
        std::net::SocketAddr::V6(_) => "[::1]:0",
    };

    let socket = io_loop
        .block_on(net::UdpSocket::bind(
            &client_addr.to_socket_addrs().unwrap().next().unwrap(),
        ))
        .expect("could not create socket"); // some random address...
    let (mut stream, sender) = UdpStream::<net::UdpSocket>::with_bound(socket);
    //let mut stream: UdpStream = io_loop.block_on(stream).ok().unwrap();

    for _ in 0..send_recv_times {
        // test once
        sender
            .unbounded_send(SerialMessage::new(test_bytes.to_vec(), server_addr))
            .unwrap();
        let (buffer_and_addr, stream_tmp) = io_loop.block_on(stream.into_future());
        stream = stream_tmp;
        let message = buffer_and_addr
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(message.bytes(), test_bytes);
        assert_eq!(message.addr(), server_addr);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
