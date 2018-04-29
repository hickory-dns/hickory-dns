// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! MDNS based DNS client connection for Client impls

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use futures::Future;
use trust_dns_proto::DnsStreamHandle;

use client::ClientConnection;
use error::*;
use multicast::{MDNS_IPV4, MDNS_IPV6, MdnsClientStream, MdnsQueryType};

/// MDNS based DNS Client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct MdnsClientConnection {
    multicast_addr: SocketAddr,
    packet_ttl: Option<u32>,
    ipv4_if: Option<Ipv4Addr>,
    ipv6_if: Option<u32>,
}

impl MdnsClientConnection {
    /// associates the socket to the well-known ipv4 multicast addess
    pub fn new_ipv4(packet_ttl: Option<u32>, ipv4_if: Option<Ipv4Addr>) -> Self {
        MdnsClientConnection {
            multicast_addr: *MDNS_IPV4,
            packet_ttl,
            ipv4_if,
            ipv6_if: None,
        }
    }

    /// associates the socket to the well-known ipv6 multicast addess
    pub fn new_ipv6(packet_ttl: Option<u32>, ipv6_if: Option<u32>) -> Self {
        MdnsClientConnection {
            multicast_addr: *MDNS_IPV6,
            packet_ttl,
            ipv4_if: None,
            ipv6_if,
        }
    }
}

impl ClientConnection for MdnsClientConnection {
    type MessageStream = MdnsClientStream;

    fn new_stream(
        &self,
    ) -> ClientResult<(
        Box<Future<Item = Self::MessageStream, Error = io::Error> + Send>,
        Box<DnsStreamHandle<Error = ClientError> + Send>,
    )> {
        let (mdns_client_stream, handle) = MdnsClientStream::new(
            self.multicast_addr,
            MdnsQueryType::OneShot,
            self.packet_ttl,
            self.ipv4_if,
            self.ipv6_if,
        );

        Ok((mdns_client_stream, handle))
    }
}
