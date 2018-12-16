// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::time::Duration;

use futures::stream::Fuse;
use futures::sync::mpsc::{unbounded, UnboundedReceiver};
use futures::{Async, Future, Poll, Stream};
use tokio_timer::{timeout::Error, Timeout};
use tokio_udp;

use error::ProtoError;
use op::Message;
use udp::udp_stream::NextRandomUdpSocket;
use udp::UdpStream;
use xfer::{
    BufStreamHandle, DnsClientStream, DnsRequest, DnsRequestSender, DnsResponse, SerialMessage,
};
use BufDnsStreamHandle;
use DnsStreamHandle;

/// A UDP client stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpClientStream {
    name_server: SocketAddr,
    outbound_messages: Fuse<UnboundedReceiver<SerialMessage>>,
    timeout: Duration,
    is_shutdown: bool,
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
        Self::with_timeout(name_server, Duration::from_secs(5))
    }

    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (UdpClientConnect, Box<DnsStreamHandle + Send>) {
        let (message_sender, outbound_messages) = unbounded();
        let message_sender = BufStreamHandle::new(message_sender);

        let new_future = UdpClientConnect {
            name_server: Some(name_server),
            outbound_messages: Some(outbound_messages.fuse()),
            timeout,
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

/// creates random query_id, each socket is unique, no need for global uniqueness
fn random_query_id() -> u16 {
    use rand::distributions::{Distribution, Standard};
    let mut rand = rand::thread_rng();

    Standard.sample(&mut rand)
}

impl DnsRequestSender for UdpClientStream {
    type DnsResponseFuture = UdpResponse;

    fn send_message(&mut self, mut message: DnsRequest) -> Self::DnsResponseFuture {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        message.set_id(random_query_id());

        let bytes = match message.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => {
                return UdpResponse(Timeout::new(
                    SingleUseUdpSocket::Errored(Some(err.into())),
                    self.timeout,
                ))
            }
        };

        let message_id = message.id();
        let message = SerialMessage::new(bytes, self.name_server);

        UdpResponse::new(message, message_id, self.timeout)
    }

    fn error_response(err: ProtoError) -> Self::DnsResponseFuture {
        UdpResponse(Timeout::new(
            SingleUseUdpSocket::Errored(Some(err.into())),
            Duration::from_secs(5), // this should never be triggered
        ))
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for UdpClientStream {
    type Item = ();
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.is_shutdown {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::Ready(Some(())))
        }
    }
}

/// A future that resolves to
pub struct UdpResponse(Timeout<SingleUseUdpSocket>);

impl UdpResponse {
    /// creates a new future for the request
    ///
    /// # Arguments
    ///
    /// * `request` - Serialized message being sent
    /// * `message_id` - Id of the message that was encoded in the serial message
    fn new(request: SerialMessage, message_id: u16, timeout: Duration) -> Self {
        UdpResponse(Timeout::new(
            SingleUseUdpSocket::StartSend(Some(request), message_id),
            timeout,
        ))
    }
}

impl Future for UdpResponse {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll().map_err(ProtoError::from)
    }
}

/// A future that resolves to an UdpClientStream
pub struct UdpClientConnect {
    name_server: Option<SocketAddr>,
    outbound_messages: Option<Fuse<UnboundedReceiver<SerialMessage>>>,
    timeout: Duration,
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
            is_shutdown: false,
            timeout: self.timeout,
        }))
    }
}

enum SingleUseUdpSocket {
    StartSend(Option<SerialMessage>, u16),
    Connect(Option<SerialMessage>, NextRandomUdpSocket, u16),
    Send(Option<SerialMessage>, Option<tokio_udp::UdpSocket>, u16),
    AwaitResponse(Option<SerialMessage>, tokio_udp::UdpSocket, u16),
    Response(Option<Message>),
    Errored(Option<ProtoError>),
}

impl Future for SingleUseUdpSocket {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            *self = match *self {
                SingleUseUdpSocket::StartSend(ref mut msg, msg_id) => {
                    println!("===============> SingleUseUdpSocket::StartSend");

                    // get a new socket to use
                    let msg = msg.take();
                    let name_server = msg
                        .as_ref()
                        .expect("SingleUseUdpSocket::StartSend invalid state: msg")
                        .addr();
                    SingleUseUdpSocket::Connect(msg, NextRandomUdpSocket::new(&name_server), msg_id)
                }
                SingleUseUdpSocket::Connect(ref mut msg, ref mut future_socket, msg_id) => {
                    println!("===============> SingleUseUdpSocket::Connect");
                    let socket = try_ready!(future_socket.poll());

                    // send the message, and then await the response
                    SingleUseUdpSocket::Send(msg.take(), Some(socket), msg_id)
                }
                SingleUseUdpSocket::Send(ref mut msg, ref mut socket, msg_id) => {
                    println!("===============> SingleUseUdpSocket::Send");

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
                        msg_id,
                    )
                }
                SingleUseUdpSocket::AwaitResponse(ref mut msg, ref mut socket, msg_id) => {
                    println!("===============> SingleUseUdpSocket::AwaitResponse before poll");

                    let mut buf = [0u8; 2048];

                    let (len, src) = try_ready!(socket.poll_recv_from(&mut buf));
                    println!("===============> SingleUseUdpSocket::AwaitResponse after poll");
                    let response = SerialMessage::new(buf.iter().take(len).cloned().collect(), src);

                    // compare expected src to received packet
                    let src = msg
                        .as_ref()
                        .expect("SingleUseUdpSocket::AwaitResponse invalid state: msg")
                        .addr();

                    // TODO: this will be dropped when merged into master
                    if response.addr() != src {
                        warn!("{} does not match name_server: {}", response.addr(), src)
                    }

                    match response.to_message() {
                        Ok(message) => {
                            if msg_id == message.id() {
                                println!(
                                    "===============> SingleUseUdpSocket::AwaitResponse got it!"
                                );

                                debug!("received message id: {}", message.id());
                                SingleUseUdpSocket::Response(Some(message))
                            } else {
                                // on wrong id, attempted poison?
                                warn!(
                                    "expected message id: {} got: {}, dropped",
                                    msg_id,
                                    message.id()
                                );
                                println!(
                                    "===============> SingleUseUdpSocket::AwaitResponse wrong id!"
                                );

                                //SingleUseUdpSocket::AwaitResponse(msg.take(), socket.take(), msg_id)
                                continue;
                            }
                        }
                        Err(e) => {
                            println!("===============> SingleUseUdpSocket::AwaitResponse bad msg!");

                            // on errors deserializing, continue
                            warn!(
                                "dropped malformed message waiting for id: {} err: {}",
                                msg_id, e
                            );
                            //SingleUseUdpSocket::AwaitResponse(msg.take(), socket.take(), msg_id)
                            continue;
                        }
                    }
                }
                SingleUseUdpSocket::Response(ref mut response) => {
                    println!("===============> SingleUseUdpSocket::Response");

                    // finally return the message
                    return Ok(Async::Ready(
                        response
                            .take()
                            .expect("SingleUseUdpSocket::Send invalid state: already complete")
                            .into(),
                    ));
                }
                SingleUseUdpSocket::Errored(ref mut error) => {
                    // finally return the message
                    return Err(error
                        .take()
                        .expect("SingleUseUdpSocket::Errored invalid state: already complete"));
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
