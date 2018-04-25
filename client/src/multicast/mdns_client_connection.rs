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
use tokio_reactor::Handle;
use trust_dns_proto::DnsStreamHandle;

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

    /// Like ClientConnection::new_stream but with a Handle as additional parameter
    /// Return the inner Futures items
    ///
    /// Consumes the connection and allows for future based operations afterward.
    pub fn new_stream(
        &self,
        handle: &Handle,
    ) -> ClientResult<(
        Box<Future<Item = MdnsClientStream, Error = io::Error>>,
        Box<DnsStreamHandle<Error = ClientError>>,
    )> {
        let (mdns_client_stream, handle) = MdnsClientStream::new(
            self.multicast_addr,
            MdnsQueryType::OneShot,
            self.packet_ttl,
            self.ipv4_if,
            self.ipv6_if,
            handle,
        );

        Ok((mdns_client_stream, handle))
    }
}
