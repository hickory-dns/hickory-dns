// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::stream::{Stream, StreamExt};
use futures_util::{future, future::Future, ready, FutureExt, TryFutureExt};
use lazy_static::lazy_static;
use log::{debug, trace};
use rand;
use rand::distributions::{uniform::Uniform, Distribution};
use socket2::{self, Socket};
use tokio::net::UdpSocket;

use crate::multicast::MdnsQueryType;
use crate::udp::UdpStream;
use crate::xfer::SerialMessage;
use crate::BufDnsStreamHandle;

pub(crate) const MDNS_PORT: u16 = 5353;
lazy_static! {
    /// mDNS ipv4 address https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    pub static ref MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,251).into(), MDNS_PORT);
    /// link-local mDNS ipv6 address https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    pub static ref MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB).into(), MDNS_PORT);
}

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct MdnsStream {
    /// Multicast address used for mDNS queries
    multicast_addr: SocketAddr,
    /// This is used for sending and (directly) receiving messages
    datagram: Option<UdpStream<UdpSocket>>,
    // FIXME: like UdpStream, this Arc is unnecessary, only needed for temp async/await capture below
    /// In one-shot multicast, this will not join the multicast group
    multicast: Option<Arc<UdpSocket>>,
    /// Receiving portion of the MdnsStream
    rcving_mcast: Option<Pin<Box<dyn Future<Output = io::Result<SerialMessage>> + Send>>>,
}

impl MdnsStream {
    /// associates the socket to the well-known ipv4 multicast address
    pub fn new_ipv4(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
    ) -> (
        Box<dyn Future<Output = Result<Self, io::Error>> + Send + Unpin>,
        BufDnsStreamHandle,
    ) {
        Self::new(*MDNS_IPV4, mdns_query_type, packet_ttl, ipv4_if, None)
    }

    /// associates the socket to the well-known ipv6 multicast address
    pub fn new_ipv6(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv6_if: Option<u32>,
    ) -> (
        Box<dyn Future<Output = Result<Self, io::Error>> + Send + Unpin>,
        BufDnsStreamHandle,
    ) {
        Self::new(*MDNS_IPV6, mdns_query_type, packet_ttl, None, ipv6_if)
    }

    /// Returns the address of the multicast network in use
    pub fn multicast_addr(&self) -> SocketAddr {
        self.multicast_addr
    }

    /// This method is available for specifying a custom Multicast address to use.
    ///
    /// In general this operates nearly identically to UDP, except that it automatically joins
    ///  the default multicast DNS addresses. See <https://tools.ietf.org/html/rfc6762#section-5>
    ///  for details.
    ///
    /// When sending ipv6 multicast packets, the interface being used is required,
    ///  this will panic if the interface is not specified for all MdnsQueryType except Passive
    ///  (which does not allow sending data)
    ///
    /// # Arguments
    ///
    /// * `multicast_addr` - address to use for multicast requests
    /// * `mdns_query_type` - true if the querier using this socket will only perform standard DNS queries over multicast.
    /// * `ipv4_if` - Address to bind to for sending multicast packets, defaults to `0.0.0.0` if not specified (not relevant for ipv6)
    /// * `ipv6_if` - Interface index for the interface to be used when sending ipv6 packets.
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn new(
        multicast_addr: SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
        ipv6_if: Option<u32>,
    ) -> (
        Box<dyn Future<Output = Result<Self, io::Error>> + Send + Unpin>,
        BufDnsStreamHandle,
    ) {
        let (message_sender, outbound_messages) = BufDnsStreamHandle::new(multicast_addr);
        let multicast_socket = match Self::join_multicast(&multicast_addr, mdns_query_type) {
            Ok(socket) => socket,
            Err(err) => return (Box::new(future::err(err)), message_sender),
        };

        // TODO: allow the bind address to be specified...
        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = Self::next_bound_local_address(
            &multicast_addr,
            mdns_query_type,
            packet_ttl,
            ipv4_if,
            ipv6_if,
        );

        // while 0 is meant to keep the packet on localhost, linux regards this as an error,
        //   while macOS (BSD?) and Windows allow it.
        if let Some(ttl) = packet_ttl {
            assert!(ttl > 0, "TTL must be greater than 0");
        }

        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream = {
            Box::new(
                next_socket
                    .map(move |socket| match socket {
                        Ok(Some(socket)) => Ok(Some(UdpSocket::from_std(socket)?)),
                        Ok(None) => Ok(None),
                        Err(err) => Err(err),
                    })
                    .map_ok(move |socket: Option<_>| {
                        let datagram: Option<_> =
                            socket.map(|socket| UdpStream::from_parts(socket, outbound_messages));
                        let multicast: Option<_> = multicast_socket.map(|multicast_socket| {
                            Arc::new(UdpSocket::from_std(multicast_socket).expect("bad handle?"))
                        });

                        Self {
                            multicast_addr,
                            datagram,
                            multicast,
                            rcving_mcast: None,
                        }
                    }),
            )
        };

        (stream, message_sender)
    }

    /// On Windows, unlike all Unix variants, it is improper to bind to the multicast address
    ///
    /// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms737550(v=vs.85).aspx
    #[cfg(windows)]
    #[cfg_attr(docsrs, doc(cfg(windows)))]
    fn bind_multicast(socket: &Socket, multicast_addr: &SocketAddr) -> io::Result<()> {
        let multicast_addr = match *multicast_addr {
            SocketAddr::V4(addr) => SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), addr.port()),
            SocketAddr::V6(addr) => {
                SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), addr.port())
            }
        };
        socket.bind(&socket2::SockAddr::from(multicast_addr))
    }

    /// On unixes we bind to the multicast address, which causes multicast packets to be filtered
    #[cfg(unix)]
    #[cfg_attr(docsrs, doc(cfg(unix)))]
    fn bind_multicast(socket: &Socket, multicast_addr: &SocketAddr) -> io::Result<()> {
        socket.bind(&socket2::SockAddr::from(*multicast_addr))
    }

    /// Returns a socket joined to the multicast address
    fn join_multicast(
        multicast_addr: &SocketAddr,
        mdns_query_type: MdnsQueryType,
    ) -> Result<Option<std::net::UdpSocket>, io::Error> {
        if !mdns_query_type.join_multicast() {
            return Ok(None);
        }

        let ip_addr = multicast_addr.ip();
        // it's an error to not use a proper mDNS address
        if !ip_addr.is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("expected multicast address for binding: {}", ip_addr),
            ));
        }

        // binding the UdpSocket to the multicast address tells the OS to filter all packets on this socket to just this
        //   multicast address
        // TODO: allow the binding interface to be specified
        let socket = match ip_addr {
            IpAddr::V4(ref mdns_v4) => {
                let socket = Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0, 0, 0, 0))?;
                socket
            }
            IpAddr::V6(ref mdns_v6) => {
                let socket = Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;

                socket.set_only_v6(true)?;
                socket.join_multicast_v6(mdns_v6, 0)?;
                socket
            }
        };

        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)] // this is currently restricted to Unix's in socket2
        socket.set_reuse_port(true)?;
        Self::bind_multicast(&socket, multicast_addr)?;

        debug!("joined {}", multicast_addr);
        Ok(Some(std::net::UdpSocket::from(socket)))
    }

    /// Creates a future for randomly binding to a local socket address for client connections.
    fn next_bound_local_address(
        multicast_addr: &SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
        ipv6_if: Option<u32>,
    ) -> NextRandomUdpSocket {
        let bind_address: IpAddr = match *multicast_addr {
            SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        };

        NextRandomUdpSocket {
            bind_address,
            mdns_query_type,
            packet_ttl,
            ipv4_if,
            ipv6_if,
        }
    }
}

impl Stream for MdnsStream {
    type Item = io::Result<SerialMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        assert!(self.datagram.is_some() || self.multicast.is_some());

        // we poll the datagram socket first, if available, since it's a direct response or direct request
        if let Some(ref mut datagram) = self.as_mut().datagram {
            match datagram.poll_next_unpin(cx) {
                Poll::Ready(ready) => return Poll::Ready(ready),
                Poll::Pending => (), // drop through
            }
        }

        loop {
            let msg = if let Some(ref mut receiving) = self.rcving_mcast {
                // TODO: should we drop this packet if it's not from the same src as dest?
                let msg = ready!(receiving.as_mut().poll_unpin(cx))?;

                Some(Poll::Ready(Some(Ok(msg))))
            } else {
                None
            };

            self.rcving_mcast = None;

            if let Some(msg) = msg {
                return msg;
            }

            // let socket = Arc::clone(socket);
            if let Some(ref socket) = self.multicast {
                let socket = Arc::clone(socket);
                let receive_future = async {
                    let socket = socket;
                    let mut buf = [0u8; 2048];
                    let (len, src) = socket.recv_from(&mut buf).await?;

                    Ok(SerialMessage::new(
                        buf.iter().take(len).cloned().collect(),
                        src,
                    ))
                };

                self.rcving_mcast = Some(Box::pin(receive_future.boxed()));
            }
        }
    }
}

#[must_use = "futures do nothing unless polled"]
struct NextRandomUdpSocket {
    bind_address: IpAddr,
    mdns_query_type: MdnsQueryType,
    packet_ttl: Option<u32>,
    ipv4_if: Option<Ipv4Addr>,
    ipv6_if: Option<u32>,
}

impl NextRandomUdpSocket {
    fn prepare_sender(&self, socket: std::net::UdpSocket) -> io::Result<std::net::UdpSocket> {
        let addr = socket.local_addr()?;
        debug!("preparing sender on: {}", addr);

        let socket = Socket::from(socket);

        // TODO: TTL doesn't work on ipv6
        match addr {
            SocketAddr::V4(..) => {
                socket.set_multicast_loop_v4(true)?;
                socket.set_multicast_if_v4(
                    &self.ipv4_if.unwrap_or_else(|| Ipv4Addr::new(0, 0, 0, 0)),
                )?;
                if let Some(ttl) = self.packet_ttl {
                    socket.set_ttl(ttl)?;
                    socket.set_multicast_ttl_v4(ttl)?;
                }
            }
            SocketAddr::V6(..) => {
                let ipv6_if = self.ipv6_if.unwrap_or_else(|| {
                    panic!("for ipv6 multicasting the interface must be specified")
                });

                socket.set_multicast_loop_v6(true)?;
                socket.set_multicast_if_v6(ipv6_if)?;
                if let Some(ttl) = self.packet_ttl {
                    socket.set_unicast_hops_v6(ttl)?;
                    socket.set_multicast_hops_v6(ttl)?;
                }
            }
        }

        Ok(std::net::UdpSocket::from(socket))
    }
}

impl Future for NextRandomUdpSocket {
    // TODO: clean this up, the RandomUdpSocket shouldnt' care about the query type
    type Output = io::Result<Option<std::net::UdpSocket>>;

    /// polls until there is an available next random UDP port.
    ///
    /// if there is no port available after 10 attempts, returns NotReady
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // non-one-shot, i.e. continuous, always use one of the well-known mdns ports and bind to the multicast addr
        if !self.mdns_query_type.sender() {
            debug!("skipping sending stream");
            Poll::Ready(Ok(None))
        } else if self.mdns_query_type.bind_on_5353() {
            let addr = SocketAddr::new(self.bind_address, MDNS_PORT);
            debug!("binding sending stream to {}", addr);
            let socket = std::net::UdpSocket::bind(&addr)?;
            let socket = self.prepare_sender(socket)?;

            Poll::Ready(Ok(Some(socket)))
        } else {
            // TODO: this is basically identical to UdpStream from here... share some code? (except for the port restriction)
            // one-shot queries look very similar to UDP socket, but can't listen on 5353

            // Per RFC 6056 Section 2.1:
            //
            //    The dynamic port range defined by IANA consists of the 49152-65535
            //    range, and is meant for the selection of ephemeral ports.
            let rand_port_range = Uniform::new_inclusive(49152_u16, u16::max_value());
            let mut rand = rand::thread_rng();

            for attempt in 0..10 {
                let port = rand_port_range.sample(&mut rand);

                // see one_shot usage info: https://tools.ietf.org/html/rfc6762#section-5
                //  the MDNS_PORT is used to signal to remote processes that this is capable of receiving multicast packets
                //  i.e. is joined to the multicast address.
                if port == MDNS_PORT {
                    trace!("unlucky, got MDNS_PORT");
                    continue;
                }

                let addr = SocketAddr::new(self.bind_address, port);
                debug!("binding sending stream to {}", addr);

                match std::net::UdpSocket::bind(&addr) {
                    Ok(socket) => {
                        let socket = self.prepare_sender(socket)?;
                        return Poll::Ready(Ok(Some(socket)));
                    }
                    Err(err) => debug!("unable to bind port, attempt: {}: {}", attempt, err),
                }
            }

            debug!("could not get next random port, delaying");

            // TODO: this replaced a task::current().notify, is it correct?
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use crate::xfer::dns_handle::DnsStreamHandle;
    use futures_util::future::Either;
    use tokio::runtime;

    // TODO: is there a better way?
    const BASE_TEST_PORT: u16 = 5379;

    lazy_static! {
        /// 250 appears to be unused/unregistered
        static ref TEST_MDNS_IPV4: IpAddr = Ipv4Addr::new(224,0,0,250).into();
        /// FA appears to be unused/unregistered
        static ref TEST_MDNS_IPV6: IpAddr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FA).into();
    }

    // one_shot tests are basically clones from the udp tests
    #[test]
    fn test_next_random_socket() {
        // use env_logger;
        // env_logger::init();

        let io_loop = runtime::Runtime::new().unwrap();
        let (stream, _) = MdnsStream::new(
            SocketAddr::new(*TEST_MDNS_IPV4, BASE_TEST_PORT),
            MdnsQueryType::OneShot,
            Some(1),
            None,
            None,
        );
        let result = io_loop.block_on(stream);

        if let Err(error) = result {
            println!("Random address error: {:#?}", error);
            panic!("failed to get next random address");
        }
    }

    // FIXME: reenable after breakage in async/await
    #[ignore]
    #[test]
    fn test_one_shot_mdns_ipv4() {
        one_shot_mdns_test(SocketAddr::new(*TEST_MDNS_IPV4, BASE_TEST_PORT + 1));
    }

    #[test]
    #[ignore]
    fn test_one_shot_mdns_ipv6() {
        one_shot_mdns_test(SocketAddr::new(*TEST_MDNS_IPV6, BASE_TEST_PORT + 2));
    }

    //   as there are probably unexpected responses coming on the standard addresses
    fn one_shot_mdns_test(mdns_addr: SocketAddr) {
        use std::time::Duration;

        let client_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let test_bytes: &'static [u8; 8] = b"DEADBEEF";
        let send_recv_times = 10;
        let client_done_clone = client_done.clone();

        // an in and out server
        let server_handle = std::thread::Builder::new()
            .name("test_one_shot_mdns:server".to_string())
            .spawn(move || {
                let server_loop = runtime::Runtime::new().unwrap();
                let mut timeout = future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
                    .flatten()
                    .boxed();

                // TTLs are 0 so that multicast test packets never leave the test host...
                // FIXME: this is hardcoded to index 5 for ipv6, which isn't going to be correct in most cases...
                let (server_stream_future, mut server_sender) = MdnsStream::new(
                    mdns_addr,
                    MdnsQueryType::OneShotJoin,
                    Some(1),
                    None,
                    Some(5),
                );

                // For one-shot responses we are competing with a system mDNS responder, we will respond from a different port...
                let mut server_stream = server_loop
                    .block_on(server_stream_future)
                    .expect("could not create mDNS listener")
                    .into_future();

                for _ in 0..=send_recv_times {
                    if client_done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    // wait for some bytes...
                    match server_loop.block_on(
                        future::lazy(|_| future::select(server_stream, timeout)).flatten(),
                    ) {
                        Either::Left((buffer_and_addr_stream_tmp, timeout_tmp)) => {
                            let (buffer_and_addr, stream_tmp): (
                                Option<Result<SerialMessage, io::Error>>,
                                MdnsStream,
                            ) = buffer_and_addr_stream_tmp;

                            server_stream = stream_tmp.into_future();
                            timeout = timeout_tmp;
                            let (buffer, addr) = buffer_and_addr
                                .expect("no msg received")
                                .expect("error receiving msg")
                                .into_parts();

                            assert_eq!(&buffer, test_bytes);
                            //println!("server got data! {}", addr);

                            // bounce them right back...
                            server_sender
                                .send(SerialMessage::new(test_bytes.to_vec(), addr))
                                .expect("could not send to client");
                        }
                        Either::Right(((), buffer_and_addr_stream_tmp)) => {
                            server_stream = buffer_and_addr_stream_tmp;
                            timeout =
                                future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
                                    .flatten()
                                    .boxed();
                        }
                    }

                    // let the server turn for a bit... send the message
                    server_loop.block_on(tokio::time::sleep(Duration::from_millis(100)));
                }
            })
            .unwrap();

        // setup the client, which is going to run on the testing thread...
        let io_loop = runtime::Runtime::new().unwrap();

        // FIXME: this is hardcoded to index 5 for ipv6, which isn't going to be correct in most cases...
        let (stream, mut sender) =
            MdnsStream::new(mdns_addr, MdnsQueryType::OneShot, Some(1), None, Some(5));
        let mut stream = io_loop.block_on(stream).ok().unwrap().into_future();
        let mut timeout = future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
            .flatten()
            .boxed();
        let mut successes = 0;

        for _ in 0..send_recv_times {
            // test once
            sender
                .send(SerialMessage::new(test_bytes.to_vec(), mdns_addr))
                .unwrap();

            println!("client sending data!");

            // TODO: this lazy isn't needed is it?
            match io_loop.block_on(future::lazy(|_| future::select(stream, timeout)).flatten()) {
                Either::Left((buffer_and_addr_stream_tmp, timeout_tmp)) => {
                    let (buffer_and_addr, stream_tmp) = buffer_and_addr_stream_tmp;
                    stream = stream_tmp.into_future();
                    timeout = timeout_tmp;

                    let (buffer, _addr) = buffer_and_addr
                        .expect("no msg received")
                        .expect("error receiving msg")
                        .into_parts();
                    println!("client got data!");

                    assert_eq!(&buffer, test_bytes);
                    successes += 1;
                }
                Either::Right(((), buffer_and_addr_stream_tmp)) => {
                    stream = buffer_and_addr_stream_tmp;
                    timeout = future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
                        .flatten()
                        .boxed();
                }
            }
        }

        client_done.store(true, std::sync::atomic::Ordering::Relaxed);
        println!("successes: {}", successes);
        assert!(successes >= 1);
        server_handle.join().expect("server thread failed");
    }

    // FIXME: reenable after breakage in async/await
    #[ignore]
    #[test]
    fn test_passive_mdns() {
        passive_mdns_test(
            MdnsQueryType::Passive,
            SocketAddr::new(*TEST_MDNS_IPV4, BASE_TEST_PORT + 3),
        )
    }

    // FIXME: reenable after breakage in async/await
    #[ignore]
    #[test]
    fn test_oneshot_join_mdns() {
        passive_mdns_test(
            MdnsQueryType::OneShotJoin,
            SocketAddr::new(*TEST_MDNS_IPV4, BASE_TEST_PORT + 4),
        )
    }

    //   as there are probably unexpected responses coming on the standard addresses
    fn passive_mdns_test(mdns_query_type: MdnsQueryType, mdns_addr: SocketAddr) {
        use std::time::Duration;

        let server_got_packet = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let test_bytes: &'static [u8; 8] = b"DEADBEEF";
        let send_recv_times = 10;
        let server_got_packet_clone = server_got_packet.clone();

        // an in and out server
        let _server_handle = std::thread::Builder::new()
            .name("test_one_shot_mdns:server".to_string())
            .spawn(move || {
                let io_loop = runtime::Runtime::new().unwrap();
                let mut timeout = future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
                    .flatten()
                    .boxed();

                // TTLs are 0 so that multicast test packets never leave the test host...
                // FIXME: this is hardcoded to index 5 for ipv6, which isn't going to be correct in most cases...
                let (server_stream_future, _server_sender) =
                    MdnsStream::new(mdns_addr, mdns_query_type, Some(1), None, Some(5));

                // For one-shot responses we are competing with a system mDNS responder, we will respond from a different port...
                let mut server_stream = io_loop
                    .block_on(server_stream_future)
                    .expect("could not create mDNS listener")
                    .into_future();

                for _ in 0..=send_recv_times {
                    // wait for some bytes...
                    match io_loop.block_on(
                        future::lazy(|_| future::select(server_stream, timeout)).flatten(),
                    ) {
                        Either::Left((_buffer_and_addr_stream_tmp, _timeout_tmp)) => {
                            // let (buffer_and_addr, stream_tmp) = buffer_and_addr_stream_tmp;

                            // server_stream = stream_tmp.into_future();
                            // timeout = timeout_tmp;
                            // let (buffer, addr) = buffer_and_addr.expect("no buffer received");

                            // assert_eq!(&buffer, test_bytes);
                            // println!("server got data! {}", addr);

                            server_got_packet_clone
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        Either::Right(((), buffer_and_addr_stream_tmp)) => {
                            server_stream = buffer_and_addr_stream_tmp;
                            timeout =
                                future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
                                    .flatten()
                                    .boxed();
                        }
                    }

                    // let the server turn for a bit... send the message
                    io_loop.block_on(tokio::time::sleep(Duration::from_millis(100)));
                }
            })
            .unwrap();

        // setup the client, which is going to run on the testing thread...
        let io_loop = runtime::Runtime::new().unwrap();
        // FIXME: this is hardcoded to index 5 for ipv6, which isn't going to be correct in most cases...
        let (stream, mut sender) =
            MdnsStream::new(mdns_addr, MdnsQueryType::OneShot, Some(1), None, Some(5));
        let mut stream = io_loop.block_on(stream).ok().unwrap().into_future();
        let mut timeout = future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
            .flatten()
            .boxed();

        for _ in 0..send_recv_times {
            // test once
            sender
                .send(SerialMessage::new(test_bytes.to_vec(), mdns_addr))
                .unwrap();

            println!("client sending data!");

            // TODO: this lazy is probably unnecessary?
            let run_result =
                io_loop.block_on(future::lazy(|_| future::select(stream, timeout)).flatten());

            if server_got_packet.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }

            match run_result {
                Either::Left((buffer_and_addr_stream_tmp, timeout_tmp)) => {
                    let (_buffer_and_addr, stream_tmp) = buffer_and_addr_stream_tmp;
                    stream = stream_tmp.into_future();
                    timeout = timeout_tmp;
                }
                Either::Right(((), buffer_and_addr_stream_tmp)) => {
                    stream = buffer_and_addr_stream_tmp;
                    timeout = future::lazy(|_| tokio::time::sleep(Duration::from_millis(100)))
                        .flatten()
                        .boxed();
                }
            }
        }

        panic!("server never got packet.");
    }
}
