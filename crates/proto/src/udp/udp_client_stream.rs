// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::time::Duration;

use futures::{Async, Future, Poll, Stream};
use tokio_timer::Timeout;
use tokio_udp;

use error::ProtoError;
use op::Message;
use udp::udp_stream::NextRandomUdpSocket;
use xfer::{DnsRequest, DnsRequestSender, DnsResponse, SerialMessage};

/// A UDP client stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct UdpClientStream {
    name_server: SocketAddr,
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
    pub fn new(name_server: SocketAddr) -> UdpClientConnect {
        Self::with_timeout(name_server, Duration::from_secs(5))
    }

    /// Constructs a new TcpStream for a client to the specified SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `name_server` - the IP and Port of the DNS server to connect to
    /// * `timeout` - connection timeout
    pub fn with_timeout(name_server: SocketAddr, timeout: Duration) -> UdpClientConnect {
        UdpClientConnect {
            name_server: Some(name_server),
            timeout,
        }
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

// TODO: is this impl necessary? there's nothing being driven here...
impl Stream for UdpClientStream {
    type Item = ();
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // Technically the Stream doesn't actually do anything.
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
                    // get a new socket to use
                    let msg = msg.take();
                    let name_server = msg
                        .as_ref()
                        .expect("SingleUseUdpSocket::StartSend invalid state: msg")
                        .addr();
                    SingleUseUdpSocket::Connect(msg, NextRandomUdpSocket::new(&name_server), msg_id)
                }
                SingleUseUdpSocket::Connect(ref mut msg, ref mut future_socket, msg_id) => {
                    let socket = try_ready!(future_socket.poll());
                    // TODO: connect the socket here on merge into master

                    // send the message, and then await the response
                    SingleUseUdpSocket::Send(msg.take(), Some(socket), msg_id)
                }
                SingleUseUdpSocket::Send(ref mut msg, ref mut socket, msg_id) => {
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
                    // TODO: consider making this heap based? need to verify it matches EDNS settings
                    let mut buf = [0u8; 2048];

                    let (len, src) = try_ready!(socket.poll_recv_from(&mut buf));
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
                                debug!("received message id: {}", message.id());
                                SingleUseUdpSocket::Response(Some(message))
                            } else {
                                // on wrong id, attempted poison?
                                warn!(
                                    "expected message id: {} got: {}, dropped",
                                    msg_id,
                                    message.id()
                                );

                                //SingleUseUdpSocket::AwaitResponse(msg.take(), socket.take(), msg_id)
                                continue;
                            }
                        }
                        Err(e) => {
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
    use op::Query;
    use rr::rdata::NULL;
    use rr::{Name, RData, Record, RecordType};
    use std::str::FromStr;
    use tokio::runtime::current_thread::Runtime;

    // use env_logger;
    // env_logger::try_init().ok();

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

    let mut query = Message::new();
    let test_name = Name::from_str("dead.beef").unwrap();
    query.add_query(Query::query(test_name.clone(), RecordType::NULL));
    let test_bytes: &'static [u8; 8] = b"DEADBEEF";
    let send_recv_times = 4;

    let test_name_server = test_name.clone();
    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name("test_udp_client_stream_ipv4:server".to_string())
        .spawn(move || {
            let mut buffer = [0_u8; 512];

            for i in 0..send_recv_times {
                // wait for some bytes...
                debug!("server receiving request {}", i);
                let (len, addr) = server.recv_from(&mut buffer).expect("receive failed");
                debug!("server received request {} from: {}", i, addr);

                let request = Message::from_vec(&buffer[0..len]).expect("failed parse of request");
                assert_eq!(*request.queries()[0].name(), test_name_server.clone());
                assert_eq!(request.queries()[0].query_type(), RecordType::NULL);

                let mut message = Message::new();
                message.set_id(request.id());
                message.add_queries(request.queries().iter().cloned().collect::<Vec<_>>());
                message.add_answer(Record::from_rdata(
                    test_name_server.clone(),
                    0,
                    RecordType::NULL,
                    RData::NULL(NULL::with(test_bytes.to_vec())),
                ));

                // bounce them right back...
                let bytes = message.to_vec().unwrap();
                debug!("server sending response {} to: {}", i, addr);
                assert_eq!(
                    server.send_to(&bytes, addr).expect("send failed"),
                    bytes.len()
                );
                debug!("server sent response {}", i);
                std::thread::yield_now();
            }
        })
        .unwrap();

    // setup the client, which is going to run on the testing thread...
    let mut io_loop = Runtime::new().unwrap();

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));
    let stream = UdpClientStream::with_timeout(server_addr, Duration::from_millis(500));
    let mut stream: UdpClientStream = io_loop.block_on(stream).ok().unwrap();
    let mut worked_once = false;

    for i in 0..send_recv_times {
        // test once
        let response_future =
            stream.send_message(DnsRequest::new(query.clone(), Default::default()));
        println!("client sending request {}", i);
        let response = match io_loop.block_on(response_future) {
            Ok(response) => response,
            Err(err) => {
                println!("failed to get message: {}", err);
                continue;
            }
        };
        println!("client got response {}", i);

        let response = Message::from(response);
        if let RData::NULL(null) = response.answers()[0].rdata() {
            assert_eq!(null.anything().expect("no bytes in NULL"), test_bytes);
        } else {
            panic!("not a NULL response");
        }

        worked_once = true;
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");

    assert!(worked_once);
}
