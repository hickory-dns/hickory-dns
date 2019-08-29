// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::net::{Ipv4Addr, SocketAddr};

use futures::{Async, Future, Poll, Stream};

use crate::error::ProtoError;
use crate::xfer::{DnsClientStream, SerialMessage};
use crate::multicast::mdns_stream::{MDNS_IPV4, MDNS_IPV6};
use crate::multicast::{MdnsQueryType, MdnsStream};
use crate::{BufDnsStreamHandle, DnsStreamHandle};

/// A UDP client stream of DNS binary packets
#[must_use = "futures do nothing unless polled"]
pub struct MdnsClientStream {
    mdns_stream: MdnsStream,
}

impl MdnsClientStream {
    /// associates the socket to the well-known ipv4 multicast address
    pub fn new_ipv4(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
    ) -> (MdnsClientConnect, Box<dyn DnsStreamHandle + Send>) {
        Self::new(*MDNS_IPV4, mdns_query_type, packet_ttl, ipv4_if, None)
    }

    /// associates the socket to the well-known ipv6 multicast address
    pub fn new_ipv6(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv6_if: Option<u32>,
    ) -> (MdnsClientConnect, Box<dyn DnsStreamHandle + Send>) {
        Self::new(*MDNS_IPV6, mdns_query_type, packet_ttl, None, ipv6_if)
    }

    /// it is expected that the resolver wrapper will be responsible for creating and managing
    ///  new UdpClients such that each new client would have a random port (reduce chance of cache
    ///  poisoning)
    ///
    /// # Return
    ///
    /// a tuple of a Future Stream which will handle sending and receiving messages, and a
    ///  handle which can be used to send messages into the stream.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        mdns_addr: SocketAddr,
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv4_if: Option<Ipv4Addr>,
        ipv6_if: Option<u32>,
    ) -> (MdnsClientConnect, Box<dyn DnsStreamHandle + Send>) {
        let (stream_future, sender) =
            MdnsStream::new(mdns_addr, mdns_query_type, packet_ttl, ipv4_if, ipv6_if);

        let new_future = Box::new(
            stream_future
                .map(move |mdns_stream| MdnsClientStream { mdns_stream })
                .map_err(ProtoError::from),
        );
        let new_future = MdnsClientConnect(new_future);

        let sender = Box::new(BufDnsStreamHandle::new(mdns_addr, sender));

        (new_future, sender)
    }
}

impl Display for MdnsClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "mDNS({})", self.mdns_stream.multicast_addr())
    }
}

impl DnsClientStream for MdnsClientStream {
    fn name_server_addr(&self) -> SocketAddr {
        self.mdns_stream.multicast_addr()
    }
}

impl Stream for MdnsClientStream {
    type Item = SerialMessage;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.mdns_stream.poll().map_err(ProtoError::from)) {
            Some(serial_message) => {
                // TODO: for mDNS queries could come from anywhere. It's not clear that there is anything
                //       we can validate in this case.
                Ok(Async::Ready(Some(serial_message)))
            }
            None => Ok(Async::Ready(None)),
        }
    }
}

/// A future that resolves to an MdnsClientStream
pub struct MdnsClientConnect(Box<dyn Future<Item = MdnsClientStream, Error = ProtoError> + Send>);

impl Future for MdnsClientConnect {
    type Item = MdnsClientStream;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}
