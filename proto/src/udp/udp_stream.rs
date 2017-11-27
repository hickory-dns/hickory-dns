// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io;

use futures::{Async, Future, Poll};
use futures::stream::{Fuse, Peekable, Stream};
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::task;
use rand;
use rand::distributions::{IndependentSample, Range};
use tokio_core;
use tokio_core::reactor::Handle;

use BufStreamHandle;
use error::*;

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpStream {
    // FIXME: change UdpStream to always select a new Socket for every request
    socket: tokio_core::net::UdpSocket,
    outbound_messages: Peekable<Fuse<UnboundedReceiver<(Vec<u8>, SocketAddr)>>>,
}

impl UdpStream {
    /// This method is intended for client connections, see `with_bound` for a method better for
    ///  straight listening. It is expected that the resolver wrapper will be responsible for
    ///  creating and managing new UdpStreams such that each new client would have a random port
    ///  (reduce chance of cache poisoning). This will return a randomly assigned local port.
    ///
    /// # Arguments
    ///
    /// * `name_server`: socket address for the remote server (used to determine IPv4 or IPv6)
    /// * `loop_handle` - handle to the IO loop
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messsages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn new<E>(
        name_server: SocketAddr,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = UdpStream, Error = io::Error>>,
        BufStreamHandle<E>,
    )
    where
        E: FromProtoError,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::<E> {
            sender: message_sender,
            phantom: PhantomData::<E>,
        };

        // TODO: allow the bind address to be specified...
        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = Self::next_bound_local_address(&name_server);

        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream: Box<Future<Item = UdpStream, Error = io::Error>> = {
            let handle = loop_handle.clone();
            Box::new(
                next_socket
                    .map(move |socket| {
                        tokio_core::net::UdpSocket::from_socket(socket, &handle)
                            .expect("something wrong with the handle?")
                    })
                    .map(move |socket| {
                        UdpStream {
                            socket: socket,
                            outbound_messages: outbound_messages.fuse().peekable(),
                        }
                    }),
            )
        };

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
    /// * `loop_handle` - handle to the IO loop
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messsages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn with_bound<E>(
        socket: std::net::UdpSocket,
        loop_handle: &Handle,
    ) -> (Self, BufStreamHandle<E>)
    where
        E: FromProtoError + 'static,
    {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::<E> {
            sender: message_sender,
            phantom: PhantomData::<E>,
        };

        // TODO: consider making this return a Result...
        let socket = tokio_core::net::UdpSocket::from_socket(socket, loop_handle)
            .expect("could not register socket to loop");

        let stream = UdpStream {
            socket: socket,
            outbound_messages: outbound_messages.fuse().peekable(),
        };

        (stream, message_sender)
    }

    /// Creates a future for randomly binding to a local socket address for client connections.
    fn next_bound_local_address(name_server: &SocketAddr) -> NextRandomUdpSocket {
        let zero_addr: IpAddr = match *name_server {
            SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        };

        NextRandomUdpSocket {
            bind_address: zero_addr,
        }
    }
}

impl Stream for UdpStream {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // this will not accept incoming data while there is data to send
        //  makes this self throttling.
        loop {
            // first try to send
            if let Async::Ready(Some(&(ref buffer, addr))) = self.outbound_messages
                .peek()
                .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
            {
                match self.socket.poll_write() {
                    Async::NotReady => return Ok(Async::NotReady),
                    Async::Ready(_) => {
                        // will return if the socket will block
                        try_nb!(self.socket.send_to(buffer, &addr));
                    }
                }
            }

            // now pop the request and check if we should break or continue.
            match self.outbound_messages
                .poll()
                .map_err(|()| io::Error::new(io::ErrorKind::Other, "unknown"))?
            {
                // already handled above, here to make sure the poll() pops the next message
                Async::Ready(Some(_)) => (),
                // now we get to drop through to the receives...
                // TODO: should we also return None if there are no more messages to send?
                Async::NotReady | Async::Ready(None) => break,
            }
        }

        // For QoS, this will only accept one message and output that
        // recieve all inbound messages

        // TODO: this should match edns settings
        let mut buf = [0u8; 2048];

        // TODO: should we drop this packet if it's not from the same src as dest?
        let (len, src) = try_nb!(self.socket.recv_from(&mut buf));
        Ok(Async::Ready(
            Some((buf.iter().take(len).cloned().collect(), src)),
        ))
    }
}

#[must_use = "futures do nothing unless polled"]
struct NextRandomUdpSocket {
    bind_address: IpAddr,
}

impl Future for NextRandomUdpSocket {
    type Item = std::net::UdpSocket;
    type Error = io::Error;

    /// polls until there is an available next random UDP port.
    ///
    /// if there is no port available after 10 attempts, returns NotReady
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let between = Range::new(1025_u32, u32::from(u16::max_value()) + 1);
        let mut rand = rand::thread_rng();

        for attempt in 0..10 {
            let port = between.ind_sample(&mut rand) as u16; // the range is [0 ... u16::max] aka [0 .. u16::max + 1)
            let zero_addr = SocketAddr::new(self.bind_address, port);

            match std::net::UdpSocket::bind(&zero_addr) {
                Ok(socket) => return Ok(Async::Ready(socket)),
                Err(err) => debug!("unable to bind port, attempt: {}: {}", attempt, err),
            }
        }

        warn!("could not get next random port, delaying");

        task::current().notify();
        // returning NotReady here, perhaps the next poll there will be some more socket available.
        Ok(Async::NotReady)
    }
}

#[test]
fn test_next_random_socket() {
    let mut io_loop = tokio_core::reactor::Core::new().unwrap();
    let (stream, _) = UdpStream::new::<ProtoError>(
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            52,
        ),
        &io_loop.handle(),
    );
    drop(
        io_loop
            .run(stream)
            .ok()
            .expect("failed to get next socket address"),
    );
}

#[test]
fn test_udp_stream_ipv4() {
    udp_stream_test(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_udp_stream_ipv6() {
    udp_stream_test(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
    ))
}

#[cfg(test)]
fn udp_stream_test(server_addr: std::net::IpAddr) {
    use tokio_core::reactor::Core;

    use std;
    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone.clone();
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
        .unwrap(); // should recieve something within 5 seconds...
    server
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should recieve something within 5 seconds...
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
    let mut io_loop = Core::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    let client_addr = match server_addr {
        std::net::SocketAddr::V4(_) => "127.0.0.1:0",
        std::net::SocketAddr::V6(_) => "[::1]:0",
    };

    let socket = std::net::UdpSocket::bind(client_addr).expect("could not create socket"); // some random address...
    let (mut stream, sender) = UdpStream::with_bound::<ProtoError>(socket, &io_loop.handle());
    //let mut stream: UdpStream = io_loop.run(stream).ok().unwrap();

    for _ in 0..send_recv_times {
        // test once
        sender
            .sender
            .unbounded_send((test_bytes.to_vec(), server_addr))
            .unwrap();
        let (buffer_and_addr, stream_tmp) = io_loop.run(stream.into_future()).ok().unwrap();
        stream = stream_tmp;
        let (buffer, addr) = buffer_and_addr.expect("no buffer received");
        assert_eq!(&buffer, test_bytes);
        assert_eq!(addr, server_addr);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
