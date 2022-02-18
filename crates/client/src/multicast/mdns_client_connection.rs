// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! MDNS based DNS client connection for Client impls

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::proto::{
    multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType, MDNS_IPV4, MDNS_IPV6},
    xfer::{DnsMultiplexer, DnsMultiplexerConnect},
};

use crate::client::{ClientConnection, Signer};

/// MDNS based DNS Client connection
///
/// Use with `trust_dns_client::client::Client` impls
#[derive(Clone, Copy)]
pub struct MdnsClientConnection {
    multicast_addr: SocketAddr,
    packet_ttl: Option<u32>,
    ipv4_if: Option<Ipv4Addr>,
    ipv6_if: Option<u32>,
}

impl MdnsClientConnection {
    /// associates the socket to the well-known ipv4 multicast address
    pub fn new_ipv4(packet_ttl: Option<u32>, ipv4_if: Option<Ipv4Addr>) -> Self {
        Self {
            multicast_addr: *MDNS_IPV4,
            packet_ttl,
            ipv4_if,
            ipv6_if: None,
        }
    }

    /// associates the socket to the well-known ipv6 multicast address
    pub fn new_ipv6(packet_ttl: Option<u32>, ipv6_if: Option<u32>) -> Self {
        Self {
            multicast_addr: *MDNS_IPV6,
            packet_ttl,
            ipv4_if: None,
            ipv6_if,
        }
    }
}

impl ClientConnection for MdnsClientConnection {
    type Sender = DnsMultiplexer<MdnsClientStream, Signer>;
    type SenderFuture = DnsMultiplexerConnect<MdnsClientConnect, MdnsClientStream, Signer>;

    fn new_stream(&self, signer: Option<Arc<Signer>>) -> Self::SenderFuture {
        let (mdns_client_stream, handle) = MdnsClientStream::new(
            self.multicast_addr,
            MdnsQueryType::OneShot,
            self.packet_ttl,
            self.ipv4_if,
            self.ipv6_if,
        );

        DnsMultiplexer::new(mdns_client_stream, handle, signer)
    }
}
