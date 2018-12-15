// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::net::SocketAddr;

use futures::stream::Fuse;
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{Async, Future, Poll, Stream};
use tokio_udp;

use error::ProtoError;
use udp::udp_stream::NextRandomUdpSocket;
use udp::UdpStream;
use xfer::{BufStreamHandle, DnsClientStream, SerialMessage};
use BufDnsStreamHandle;
use DnsStreamHandle;

/// A UDP client stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpClientStream {
    name_server: SocketAddr,
    outbound_messages: Fuse<UnboundedReceiver<SerialMessage>>,
}

impl UdpClientStream {
    /// it is expected that the resolver wrapper will be responsible for creating and managing
    ///  new UdpClients such that each new client would have a random port (reduce chance of cache
    ///  poisoning)
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messsages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn new(name_server: SocketAddr) -> (UdpClientConnect, Box<DnsStreamHandle + Send>) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        let new_future = UdpClientConnect {
            name_server: Some(name_server),
            outbound_messages: Some(outbound_messages.fuse()),
        };

        let sender = Box::new(BufDnsStreamHandle::new(name_server, message_sender));

        (new_future, sender)
    }
}

impl Display for UdpClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "UDP({})", self.name_server)
    }
}

impl DnsClientStream for UdpClientStream {
    fn name_server_addr(&self) -> SocketAddr {
        self.name_server
    }
}

impl Stream for UdpClientStream {
    type Item = UdpResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let message = try_ready!(self
            .outbound_messages
            .poll()
            .map_err(|_| ProtoError::from("outbound_messages in error state")));

        match message {
            Some(message) => Ok(Async::Ready(Some(UdpResponse::new(message)))),
            None => Ok(Async::Ready(None)),
        }
    }
}

/// A future that resolves to
pub struct UdpResponse(SingleUseUdpSocket);

impl UdpResponse {
    /// creates a new future for the request
    fn new(request: SerialMessage) -> Self {
        UdpResponse(SingleUseUdpSocket::StartSend(Some(request)))
    }
}

impl Future for UdpResponse {
    type Item = SerialMessage;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// A future that resolves to an UdpClientStream
pub struct UdpClientConnect {
    name_server: Option<SocketAddr>,
    outbound_messages: Option<Fuse<UnboundedReceiver<SerialMessage>>>,
}

impl Future for UdpClientConnect {
    type Item = UdpClientStream;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::Ready(UdpClientStream {
            name_server: self
                .name_server
                .take()
                .expect("UdpClientConnect invalid state: name_server"),
            outbound_messages: self
                .outbound_messages
                .take()
                .expect("UdpClientConnect invalid state: outbound_messages"),
        }))
    }
}

enum SingleUseUdpSocket {
    StartSend(Option<SerialMessage>),
    Connect(Option<SerialMessage>, NextRandomUdpSocket),
    Send(Option<SerialMessage>, Option<tokio_udp::UdpSocket>),
    AwaitResponse(Option<SerialMessage>, tokio_udp::UdpSocket),
    Response(Option<SerialMessage>),
}

impl Future for SingleUseUdpSocket {
    type Item = SerialMessage;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            *self = match *self {
                SingleUseUdpSocket::StartSend(ref mut msg) => {
                    // get a new socket to use
                    let msg = msg.take();
                    let name_server = msg
                        .as_ref()
                        .expect("SingleUseUdpSocket::StartSend invalid state: msg")
                        .addr();
                    SingleUseUdpSocket::Connect(msg, NextRandomUdpSocket::new(&name_server))
                }
                SingleUseUdpSocket::Connect(ref mut msg, ref mut future_socket) => {
                    let socket = try_ready!(future_socket.poll());

                    // send the message, and then await the response
                    SingleUseUdpSocket::Send(msg.take(), Some(socket))
                }
                SingleUseUdpSocket::Send(ref mut msg, ref mut socket) => {
                    try_ready!(socket
                        .as_mut()
                        .expect("SingleUseUdpSocket::Send invalid state: socket1")
                        .poll_send_to(
                            msg.as_ref()
                                .expect("SingleUseUdpSocket::Send invalid state: msg1")
                                .bytes(),
                            &msg.as_ref()
                                .expect("SingleUseUdpSocket::Send invalid state: msg2")
                                .addr()
                        ));

                    // message is sent, await the response
                    SingleUseUdpSocket::AwaitResponse(
                        msg.take(),
                        socket
                            .take()
                            .expect("SingleUseUdpSocket::Send invalid state: socket2"),
                    )
                }
                SingleUseUdpSocket::AwaitResponse(ref mut msg, ref mut socket) => {
                    let mut buf = [0u8; 2048];

                    let (len, src) = try_ready!(socket.poll_recv_from(&mut buf));
                    let response = SerialMessage::new(buf.iter().take(len).cloned().collect(), src);

                    // compare expected src to received packet
                    let src = msg
                        .as_ref()
                        .expect("SingleUseUdpSocket::AwaitResponse invalid state: msg")
                        .addr();
                    if response.addr() != src {
                        warn!("{} does not match name_server: {}", response.addr(), src)
                    }

                    SingleUseUdpSocket::Response(Some(response))
                }
                SingleUseUdpSocket::Response(ref mut response) => {
                    // finally return the message
                    return Ok(Async::Ready(response.take().expect(
                        "SingleUseUdpSocket::Send invalid state: already complete",
                    )));
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[cfg(test)]
use std::net::Ipv6Addr;
#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_udp_client_stream_ipv4() {
    udp_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

#[test]
#[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
fn test_udp_client_stream_ipv6() {
    udp_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
}

#[cfg(test)]
fn udp_client_stream_test(server_addr: IpAddr) {
    use tokio::runtime::current_thread::Runtime;

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
        .name("test_udp_client_stream_ipv4:server".to_string())
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
    let mut io_loop = Runtime::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));
    let (stream, mut sender) = UdpClientStream::new(server_addr);
    let mut stream: UdpClientStream = io_loop.block_on(stream).ok().unwrap();

    for _ in 0..send_recv_times {
        // test once
        sender
            .send(SerialMessage::new(test_bytes.to_vec(), server_addr))
            .unwrap();
        let (buffer, stream_tmp) = io_loop.block_on(stream.into_future()).ok().unwrap();
        stream = stream_tmp;
        assert_eq!(buffer.expect("no buffer received").bytes(), test_bytes);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
