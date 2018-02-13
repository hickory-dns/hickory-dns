// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::io;

use futures::{Async, Future, Poll, Stream};
use tokio_core::reactor::Handle;

use BufDnsStreamHandle;
use DnsStreamHandle;
use error::*;
use multicast::{MdnsQueryType, MdnsStream};
use multicast::mdns_stream::{MDNS_IPV4, MDNS_IPV6, MDNS_PORT};

/// A UDP client stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct MdnsClientStream {
    mdns_addr: SocketAddr,
    udp_stream: MdnsStream,
}

impl MdnsClientStream {
/// associates the socket to the well-known ipv4 multicast addess
    pub fn new_ipv4<E>(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = MdnsClientStream, Error = io::Error>>,
        Box<DnsStreamHandle<Error = E>>,
    )
    where
        E: FromProtoError + 'static,
    {
        Self::new::<E>(
            SocketAddr::new(*MDNS_IPV4, MDNS_PORT),
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
        Box<Future<Item = MdnsClientStream, Error = io::Error>>,
        Box<DnsStreamHandle<Error = E>>,
    )
    where
        E: FromProtoError + 'static,
    {
        Self::new::<E>(
            SocketAddr::new(*MDNS_IPV6, MDNS_PORT),
            mdns_query_type,
            packet_ttl,
            loop_handle,
        )
    }

    /// it is expected that the resolver wrapper will be responsible for creating and managing
    ///  new UdpClients such that each new client would have a random port (reduce chance of cache
    ///  poisoning)
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messsages, and a
    ///  handle which can be used to send messages into the stream.
    fn new<E>(
        mdns_addr: SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        loop_handle: &Handle,
    ) -> (
        Box<Future<Item = MdnsClientStream, Error = io::Error>>,
        Box<DnsStreamHandle<Error = E>>,
    )
    where
        E: FromProtoError + 'static,
    {
        let (stream_future, sender) = MdnsStream::new(mdns_addr, mdns_query_type, packet_ttl, loop_handle);

        let new_future: Box<Future<Item = MdnsClientStream, Error = io::Error>> =
            Box::new(stream_future.map(move |udp_stream| {
                MdnsClientStream {
                    mdns_addr: mdns_addr,
                    udp_stream: udp_stream,
                }
            }));

        let sender = Box::new(BufDnsStreamHandle {
            name_server: mdns_addr,
            sender: sender,
        });

        (new_future, sender)
    }
}

impl Stream for MdnsClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.udp_stream.poll()) {
            Some((buffer, src_addr)) => {
                if src_addr != self.mdns_addr
         {
                    debug!(
                        "{} does not match mdns_addr
                : {}",
                        src_addr,
                        self.mdns_addr
                
                    )
                }

                Ok(Async::Ready(Some(buffer)))
            }
            None => Ok(Async::Ready(None)),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(not(target_os = "linux"))]
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn test_mdns_client_stream_ipv4() {
        mdns_client_stream_test(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    #[test]
    #[cfg(not(target_os = "linux"))] // ignored until Travis-CI fixes IPv6
    fn test_mdns_client_stream_ipv6() {
        mdns_client_stream_test(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
    }

    #[cfg(test)]
    fn mdns_client_stream_test(server_addr: IpAddr) {
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
            .name("test_mdns_client_stream_ipv4:server".to_string())
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
        // let timeout = Timeout::new(Duration::from_secs(5), &io_loop.handle());
        let (stream, mut sender) = MdnsClientStream::new::<ProtoError>(server_addr, MdnsQueryType::OneShot, None, &io_loop.handle());
        let mut stream: MdnsClientStream = io_loop.run(stream).ok().unwrap();

        for _ in 0..send_recv_times {
            // test once
            sender.send(test_bytes.to_vec()).unwrap();
            let (buffer, stream_tmp) = io_loop.run(stream.into_future()).ok().unwrap();
            stream = stream_tmp;
            assert_eq!(&buffer.expect("no buffer received"), test_bytes);
        }

        succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
        server_handle.join().expect("server thread failed");
    }
}