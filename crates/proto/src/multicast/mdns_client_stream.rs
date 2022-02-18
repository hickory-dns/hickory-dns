// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::{Future, FutureExt, TryFutureExt};
use futures_util::stream::{Stream, StreamExt, TryStreamExt};

use crate::error::ProtoError;
use crate::multicast::mdns_stream::{MDNS_IPV4, MDNS_IPV6};
use crate::multicast::{MdnsQueryType, MdnsStream};
use crate::xfer::{DnsClientStream, SerialMessage};
use crate::{BufDnsStreamHandle, TokioTime};

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
    ) -> (MdnsClientConnect, BufDnsStreamHandle) {
        Self::new(*MDNS_IPV4, mdns_query_type, packet_ttl, ipv4_if, None)
    }

    /// associates the socket to the well-known ipv6 multicast address
    pub fn new_ipv6(
        mdns_query_type: MdnsQueryType,
        packet_ttl: Option<u32>,
        ipv6_if: Option<u32>,
    ) -> (MdnsClientConnect, BufDnsStreamHandle) {
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
    ) -> (MdnsClientConnect, BufDnsStreamHandle) {
        let (stream_future, sender) =
            MdnsStream::new(mdns_addr, mdns_query_type, packet_ttl, ipv4_if, ipv6_if);

        let stream_future = stream_future
            .map_ok(move |mdns_stream| Self { mdns_stream })
            .map_err(ProtoError::from);

        let new_future = Box::new(stream_future);
        let new_future = MdnsClientConnect(new_future);

        (new_future, sender)
    }
}

impl Display for MdnsClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "mDNS({})", self.mdns_stream.multicast_addr())
    }
}

impl DnsClientStream for MdnsClientStream {
    type Time = TokioTime;

    fn name_server_addr(&self) -> SocketAddr {
        self.mdns_stream.multicast_addr()
    }
}

impl Stream for MdnsClientStream {
    type Item = Result<SerialMessage, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mdns_stream = &mut self.as_mut().mdns_stream;
        mdns_stream.map_err(ProtoError::from).poll_next_unpin(cx)
        // match ready!(self.mdns_stream.poll_next_unpin(cx).map_err(ProtoError::from)) {
        //     Some(serial_message) => {
        //         // TODO: for mDNS queries could come from anywhere. It's not clear that there is anything
        //         //       we can validate in this case.
        //         Poll::Ready(Some(Ok(serial_message)))
        //     }
        //     None => Poll::Ready(None),
        // }
    }
}

/// A future that resolves to an MdnsClientStream
pub struct MdnsClientConnect(
    Box<dyn Future<Output = Result<MdnsClientStream, ProtoError>> + Send + Unpin>,
);

impl Future for MdnsClientConnect {
    type Output = Result<MdnsClientStream, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll_unpin(cx)
    }
}
