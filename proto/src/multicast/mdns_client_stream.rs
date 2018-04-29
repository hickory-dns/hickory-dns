// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use futures::{Async, Future, Poll, Stream};

use BufDnsStreamHandle;
use DnsStreamHandle;
use error::*;
use multicast::mdns_stream::{MDNS_IPV4, MDNS_IPV6};
use multicast::{MdnsQueryType, MdnsStream};

/// A UDP client stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct MdnsClientStream {
    mdns_stream: MdnsStream,
}

impl MdnsClientStream {
    /// associates the socket to the well-known ipv4 multicast addess
    pub fn new_ipv4<E>(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
    ) -> (
        Box<Future<Item = MdnsClientStream, Error = io::Error> + Send>,
        Box<DnsStreamHandle<Error = E> + Send>,
    )
    where
        E: FromProtoError + Send + 'static,
    {
        Self::new::<E>(
            *MDNS_IPV4,
            mdns_query_type,
            packet_ttl,
            ipv4_if,
            None,
        )
    }

    /// associates the socket to the well-known ipv6 multicast addess
    pub fn new_ipv6<E>(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv6_if: Option<u32>,
    ) -> (
        Box<Future<Item = MdnsClientStream, Error = io::Error> + Send>,
        Box<DnsStreamHandle<Error = E> + Send>,
    )
    where
        E: FromProtoError + Send + 'static,
    {
        Self::new::<E>(
            *MDNS_IPV6,
            mdns_query_type,
            packet_ttl,
            None,
            ipv6_if,
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
    pub fn new<E>(
        mdns_addr: SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
        ipv6_if: Option<u32>,
    ) -> (
        Box<Future<Item = MdnsClientStream, Error = io::Error> + Send>,
        Box<DnsStreamHandle<Error = E> + Send>,
    )
    where
        E: FromProtoError + Send + 'static,
    {
        let (stream_future, sender) = MdnsStream::new(
            mdns_addr,
            mdns_query_type,
            packet_ttl,
            ipv4_if,
            ipv6_if,
        );

        let new_future =
            Box::new(stream_future.map(move |mdns_stream| MdnsClientStream {
                mdns_stream: mdns_stream,
            }));

        let sender = Box::new(BufDnsStreamHandle::new(mdns_addr, sender));

        (new_future, sender)
    }
}

impl Stream for MdnsClientStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.mdns_stream.poll()) {
            Some((buffer, _src_addr)) => {
                // TODO: for mDNS queries could come from anywhere. It's not clear that there is anything
                //       we can validate in this case.
                Ok(Async::Ready(Some(buffer)))
            }
            None => Ok(Async::Ready(None)),
        }
    }
}
