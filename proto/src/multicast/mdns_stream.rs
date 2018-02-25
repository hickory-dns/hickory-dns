// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
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
use futures::future;
use futures::stream::Stream;
use futures::sync::mpsc::unbounded;
use futures::task;
use net2;
use rand;
use rand::distributions::{IndependentSample, Range};
use tokio_core;
use tokio_core::reactor::Handle;

use multicast::MdnsQueryType;
use udp::UdpStream;
use BufStreamHandle;
use error::*;

pub const MDNS_PORT: u16 = 5353;
lazy_static! {
    /// mDNS ipv4 address https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    pub static ref MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,251).into(), MDNS_PORT);
    /// link-local mDNS ipv6 address https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    pub static ref MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB).into(), MDNS_PORT);
}

/// A UDP stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct MdnsStream{
    /// This is used for sending and (directly) receiving messages 
    datagram: Option<UdpStream>,
    /// In one-shot multicast, this will not join the multicast group
    multicast: Option<tokio_core::net::UdpSocket>,
}

impl MdnsStream {
    /// associates the socket to the well-known ipv4 multicast addess
    pub fn new_ipv4<E>(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = MdnsStream, Error = io::Error>>,
        BufStreamHandle<E>,
    )
    where
        E: FromProtoError,
    {
        Self::new::<E>(
            *MDNS_IPV4,
            mdns_query_type,
            packet_ttl,
            loop_handle,
        )
    }

    /// associates the socket to the well-known ipv6 multicast addess
    pub fn new_ipv6<E>(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = MdnsStream, Error = io::Error>>,
        BufStreamHandle<E>,
    )
    where
        E: FromProtoError,
    {
        Self::new::<E>(
            *MDNS_IPV6,
            mdns_query_type,
            packet_ttl,
            loop_handle,
        )
    }

    /// This method is available for specifying a custom Multicast address to use.
    ///
    /// In general this operates nearly identically to UDP, except that it automatically joins
    ///  the default multicast DNS addresses. See https://tools.ietf.org/html/rfc6762#section-5
    ///  for details.
    ///
    /// # Arguments
    ///
    /// * `multicast_addr` - address to use for multicast requests
    /// * `mdns_query_type` - true if the querier using this socket will only perform standard DNS queries over multicast.
    /// * `loop_handle` - handle to the IO loop
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messsages, and a
    ///  handle which can be used to send messages into the stream.
    pub fn new<E>(
        multicast_addr: SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = MdnsStream, Error = io::Error>>,
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

        let multicast_socket = match Self::join_multicast(&multicast_addr, mdns_query_type) {
            Ok(socket) => socket,
            Err(err) => return (Box::new(future::err(err)), message_sender),
        };

        // TODO: allow the bind address to be specified...
        // constructs a future for getting the next randomly bound port to a UdpSocket
        let next_socket = Self::next_bound_local_address(&multicast_addr, mdns_query_type, packet_ttl);
        
        // This set of futures collapses the next udp socket into a stream which can be used for
        //  sending and receiving udp packets.
        let stream: Box<Future<Item = MdnsStream, Error = io::Error>> = {
            let handle = loop_handle.clone();
            let handle_clone = loop_handle.clone();
            
            Box::new(
                next_socket
                    .map(move |socket: Option<_>| {
                        socket.map(|socket| tokio_core::net::UdpSocket::from_socket(socket, &handle).expect("bad handle?"))
                    })
                    .map(move |socket: Option<_>| {
                        let datagram = socket.map(|socket| UdpStream::from_parts(socket, outbound_messages));
                        let multicast: Option<tokio_core::net::UdpSocket> = multicast_socket.map(|multicast_socket| tokio_core::net::UdpSocket::from_socket(multicast_socket, &handle_clone).expect("bad handle?"));

                        MdnsStream{datagram, multicast}
                    }),
            )
        };

        (stream, message_sender)
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
            return Err(io::Error::new(io::ErrorKind::Other, format!("expected multicast address for binding: {}", ip_addr)))
        }

        // binding the UdpSocket to the multicast address tells the OS to filter all packets on thsi socket to just this
        //   multicast address
        // TODO: allow the binding interface to be specified
        let socket = match ip_addr {
            IpAddr::V4(ref mdns_v4) => {
                let builder = net2::UdpBuilder::new_v4()?;
                builder.reuse_address(true)?;
                
                let socket = builder.bind(multicast_addr)?;
                socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0, 0, 0, 0))?;
                socket.set_multicast_loop_v4(true)?;
                
                socket
            },
            IpAddr::V6(ref mdns_v6) => {
                let builder = net2::UdpBuilder::new_v6()?;
                builder.reuse_address(true)?;
                builder.only_v6(true)?;
             
                let socket = builder.bind(multicast_addr)?;
                socket.join_multicast_v6(mdns_v6, 0)?;
                socket.set_multicast_loop_v6(true)?;
             
                socket
            },
        };

        Ok(Some(socket))
    }

    /// Creates a future for randomly binding to a local socket address for client connections.
    fn next_bound_local_address(
        multicast_addr: &SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
    ) -> NextRandomUdpSocket {
        let bind_address: IpAddr = match *multicast_addr {
            SocketAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            SocketAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        };

        NextRandomUdpSocket {
            bind_address,
            mdns_query_type,
            packet_ttl,
        }
    }
}

impl Stream for MdnsStream {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        assert!(self.datagram.is_some() || self.multicast.is_some());
        
        // we poll the datagram socket first, if available, since it's a direct response or direct request
        if let Some(ref mut datagram) = self.datagram {
            match datagram.poll() {
                Ok(Async::Ready(data)) => return Ok(Async::Ready(data)),
                Err(err) => return Err(err),
                Ok(Async::NotReady) => (), // drop through
            }
        }

        if let Some(ref mut multicast) = self.multicast {
            let mut buf = [0u8; 2048];

            // TODO: should we drop this packet if it's not from the same src as dest?
            let (len, src) = try_nb!(multicast.recv_from(&mut buf));
            // now return the multicast 
            return Ok(Async::Ready(
                Some((buf.iter().take(len).cloned().collect(), src)),
            ));
        }

        Ok(Async::NotReady)
    }
}

#[must_use = "futures do nothing unless polled"]
struct NextRandomUdpSocket {
    bind_address: IpAddr,
    mdns_query_type: MdnsQueryType,
    packet_ttl: Option<u32>,
}

impl Future for NextRandomUdpSocket {
    type Item = Option<std::net::UdpSocket>;
    type Error = io::Error;

    /// polls until there is an available next random UDP port.
    ///
    /// if there is no port available after 10 attempts, returns NotReady
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // non-one-shot, i.e. continuous, always use one of the well-known mdns ports and bind to the multicast addr
        if !self.mdns_query_type.sender() {
            Ok(Async::Ready(None))
        } else if self.mdns_query_type.bind_on_5353() {
            let addr = SocketAddr::new(self.bind_address, MDNS_PORT);
            let socket = std::net::UdpSocket::bind(&addr)?;

            Ok(Async::Ready(Some(socket)))
        } else {
            // TODO: this is basically identical to UdpStream from here... share some code? (except for the port restriction)
            // one-shot queries look very similar to UDP socket, but can't listen on 5353
            let between = Range::new(1025_u32, u32::from(u16::max_value()) + 1);
            let mut rand = rand::thread_rng();

            for attempt in 0..10 {
                let port = between.ind_sample(&mut rand) as u16; // the range is [0 ... u16::max] aka [0 .. u16::max + 1)

                // see one_shot usage info: https://tools.ietf.org/html/rfc6762#section-5
                //  the MDNS_PORT is used to signal to remote processes that this is capable of recieving multicast packets
                //  i.e. is joined to the multicast address.
                if port == MDNS_PORT {
                    trace!("unlucky, got MDNS_PORT");
                    continue;
                }

                let addr = SocketAddr::new(self.bind_address, port);

                match std::net::UdpSocket::bind(&addr) {
                    Ok(socket) => {
                        // TODO: TTL doesn't work on ipv6
                        match addr {
                            SocketAddr::V4(..) => {
                                socket.set_multicast_loop_v4(true)?;
                                if let Some(ttl) = self.packet_ttl {
                                    socket.set_ttl(ttl)?;
                                    socket.set_multicast_ttl_v4(ttl)?;
                                }
                            },
                            SocketAddr::V6(..) => {
                                socket.set_multicast_loop_v6(true)?;
                                // TODO: setting TTL fails on macOS in ipv6
                                // if let Some(ttl) = self.packet_ttl {
                                //     socket.set_ttl(ttl)?;                                
                                // } 

                            },
                        
                        }
                        return Ok(Async::Ready(Some(socket)))
                    },
                    Err(err) => debug!("unable to bind port, attempt: {}: {}", attempt, err),
                }
            }

            warn!("could not get next random port, delaying");

            task::current().notify();
            // returning NotReady here, perhaps the next poll there will be some more socket available.
            Ok(Async::NotReady)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use futures::future::{Either, Future};
    use tokio_core;
    use super::*;

    lazy_static! {
        /// 250 appears to be unused/unregistered
        static ref TEST_MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,250).into(), MDNS_PORT);
        /// FA appears to be unused/unregistered
        static ref TEST_MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FA).into(), MDNS_PORT);
    }

    // one_shot tests are basically clones from the udp tests
    #[test]
    fn test_next_random_socket() {
        let mut io_loop = tokio_core::reactor::Core::new().unwrap();
        let (stream, _) = MdnsStream::new::<ProtoError>(
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                52,
            ),
            MdnsQueryType::OneShot,
            Some(0),
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
    fn test_one_shot_mdns_ipv4() {
       one_shot_mdns_test(*TEST_MDNS_IPV4);
    }

    #[test]
    fn test_one_shot_mdns_ipv6() {
       one_shot_mdns_test(*TEST_MDNS_IPV6);
    }

    //   as there are probably unexpected responses coming on the standard addresses
    fn one_shot_mdns_test(mdns_addr: SocketAddr) {
        use tokio_core::reactor::{Core, Timeout};
        use std;
        use std::time::Duration;

        let client_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        
        let test_bytes: &'static [u8; 8] = b"DEADBEEF";
        let send_recv_times = 10;
        let client_done_clone = client_done.clone();

        // an in and out server
        let server_handle = std::thread::Builder::new()
            .name("test_one_shot_mdns:server".to_string())
            .spawn(move || {
                let mut server_loop = Core::new().unwrap();
                let loop_handle = server_loop.handle();
                let mut timeout = Timeout::new(Duration::from_millis(100), &loop_handle).expect("failed to register timeout");

                // TTLs are 0 so that multicast test packets never leave the test host...
                let (server_stream_future, server_sender) = MdnsStream::new::<ProtoError>(mdns_addr, MdnsQueryType::OneShotJoin, Some(1), &server_loop.handle());

                // For one-shot responses we are competing with a system mDNS responder, we will respond from a different port...
                let mut server_stream = server_loop.run(server_stream_future).expect("could not create mDNS listener").into_future();

                for _ in 0..(send_recv_times + 1) {
                    if client_done_clone.load(std::sync::atomic::Ordering::Relaxed) { return }
                    // wait for some bytes...
                    match server_loop.run(server_stream.select2(timeout)).ok().expect("server stream closed") {
                        Either::A((buffer_and_addr_stream_tmp, timeout_tmp)) => {
                            let (buffer_and_addr, stream_tmp) = buffer_and_addr_stream_tmp;

                            server_stream = stream_tmp.into_future();
                            timeout = timeout_tmp;
                            let (buffer, addr) = buffer_and_addr.expect("no buffer received");
                        
                            assert_eq!(&buffer, test_bytes);
                            println!("server got data! {}", addr);

                            // bounce them right back...
                            server_sender
                                .unbounded_send((test_bytes.to_vec(), addr))
                                .expect("could not send to client");

                        }
                        Either::B(((), buffer_and_addr_stream_tmp)) => {
                            server_stream = buffer_and_addr_stream_tmp;
                            timeout = Timeout::new(Duration::from_millis(100), &loop_handle).expect("failed to register timeout");
                        }
                    }

                    // let the server turn for a bit... send the message
                    server_loop.turn(Some(Duration::from_millis(100)));
                }
            })
            .unwrap();

        // setup the client, which is going to run on the testing thread...
        let mut io_loop = Core::new().unwrap();
        let loop_handle = io_loop.handle();
        let (stream, sender) = MdnsStream::new::<ProtoError>(mdns_addr, MdnsQueryType::OneShot, Some(1), &loop_handle);
        let mut stream = io_loop.run(stream).ok().unwrap().into_future();
        let mut timeout = Timeout::new(Duration::from_secs(100), &io_loop.handle()).expect("failed to register timeout");
        let mut successes = 0;

        for _ in 0..send_recv_times {
            // test once
            sender
                .unbounded_send((test_bytes.to_vec(), mdns_addr))
                .unwrap();

            println!("client sending data!");
            
            let run_result = match io_loop.run(stream.select2(timeout)) {
                Ok(run_result) => run_result,
                Err(err) => match err {
                    Either::A(((stream_err, _stream), _timeout)) => panic!("client stream errored: {}", stream_err),
                    Either::B((timeout_err, _stream)) => panic!("client timeout errored: {}", timeout_err),
                }
            };

            match run_result {
                Either::A((buffer_and_addr_stream_tmp, timeout_tmp)) => {
                    let (buffer_and_addr, stream_tmp) = buffer_and_addr_stream_tmp;
                    stream = stream_tmp.into_future();
                    timeout = timeout_tmp;

                    let (buffer, _addr) = buffer_and_addr.expect("no buffer received");
                    println!("client got data!");

                    assert_eq!(&buffer, test_bytes);
                    successes += 1;
                }
                Either::B(((), buffer_and_addr_stream_tmp)) => {
                    stream = buffer_and_addr_stream_tmp;
                    timeout = Timeout::new(Duration::from_millis(100), &loop_handle).expect("failed to register timeout");
                }
            }
        }

        client_done.store(true, std::sync::atomic::Ordering::Relaxed);
        println!("successes: {}", successes);
        assert!(successes >= 1);
        server_handle.join().expect("server thread failed");
    }

    // #[cfg(test)]
    // fn mdns_continuous_test(server_addr: std::net::IpAddr) {
    //     use tokio_core::reactor::Core;

    //     use std;
    //     let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    //     let succeeded_clone = succeeded.clone();
    //     std::thread::Builder::new()
    //         .name("thread_killer".to_string())
    //         .spawn(move || {
    //             let succeeded = succeeded_clone.clone();
    //             for _ in 0..15 {
    //                 std::thread::sleep(std::time::Duration::from_secs(1));
    //                 if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
    //                     return;
    //                 }
    //             }

    //             panic!("timeout");
    //         })
    //         .unwrap();

    //     let server = std::net::UdpSocket::bind(SocketAddr::new(server_addr, 0)).unwrap();
    //     server
    //         .set_read_timeout(Some(std::time::Duration::from_secs(5)))
    //         .unwrap(); // should recieve something within 5 seconds...
    //     server
    //         .set_write_timeout(Some(std::time::Duration::from_secs(5)))
    //         .unwrap(); // should recieve something within 5 seconds...
    //     let server_addr = server.local_addr().unwrap();

    //     let test_bytes: &'static [u8; 8] = b"DEADBEEF";
    //     let send_recv_times = 4;

    //     // an in and out server
    //     let server_handle = std::thread::Builder::new()
    //         .name("test_mdns_stream_ipv4:server".to_string())
    //         .spawn(move || {
    //             let mut buffer = [0_u8; 512];

    //             for _ in 0..send_recv_times {
    //                 // wait for some bytes...
    //                 let (len, addr) = server.recv_from(&mut buffer).expect("receive failed");

    //                 assert_eq!(&buffer[0..len], test_bytes);

    //                 // bounce them right back...
    //                 assert_eq!(
    //                     server.send_to(&buffer[0..len], addr).expect("send failed"),
    //                     len
    //                 );
    //             }
    //         })
    //         .unwrap();

    //     // setup the client, which is going to run on the testing thread...
    //     let mut io_loop = Core::new().unwrap();

    //     // the tests should run within 5 seconds... right?
    //     // TODO: add timeout here, so that test never hangs...
    //     let client_addr = match server_addr {
    //         std::net::SocketAddr::V4(_) => "127.0.0.1:0",
    //         std::net::SocketAddr::V6(_) => "[::1]:0",
    //     };

    //     let socket = std::net::UdpSocket::bind(client_addr).expect("could not create socket"); // some random address...
    //     let (mut stream, sender) = MdnsStream::with_bound::<ProtoError>(socket, &io_loop.handle());
    //     //let mut stream: MdnsStream = io_loop.run(stream).ok().unwrap();

    //     for _ in 0..send_recv_times {
    //         // test once
    //         sender
    //             .sender
    //             .unbounded_send((test_bytes.to_vec(), server_addr))
    //             .unwrap();
    //         let (buffer_and_addr, stream_tmp) = io_loop.run(stream.into_future()).ok().unwrap();
    //         stream = stream_tmp;
    //         let (buffer, addr) = buffer_and_addr.expect("no buffer received");
    //         assert_eq!(&buffer, test_bytes);
    //         assert_eq!(addr, server_addr);
    //     }

    //     succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    //     server_handle.join().expect("server thread failed");
    // }
}
