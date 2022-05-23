// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Multicast protocol related components for DNS

mod mdns_client_stream;
mod mdns_stream;

pub use self::mdns_client_stream::{MdnsClientConnect, MdnsClientStream};
pub use self::mdns_stream::{MdnsStream, MDNS_IPV4, MDNS_IPV6};

/// See [rfc6762](https://tools.ietf.org/html/rfc6762#section-5) details on these different types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsQueryType {
    /// The querier using this socket will only perform standard DNS queries over multicast. (clients only)
    ///
    /// Effectively treats mDNS as essentially no different than any other DNS query; one request followed by one response.
    ///   Only one UDP socket will be created.
    OneShot,
    /// The querier is fully compliant with [rfc6762](https://tools.ietf.org/html/rfc6762#section-5). (servers, clients)
    ///
    /// mDNS capable clients will sent messages with many queries, and they will expect many responses. Two UDP sockets will be
    ///   created, one for receiving multicast traffic, the other used for sending queries and direct responses. This requires
    ///   port 5353 to be available on the system (many modern OSes already have mDNSResponders running taking this port).
    Continuous,
    /// The querier operates under the OneShot semantics, but also joins the multicast group. (non-compliant servers, clients)
    ///
    /// This is not defined in the mDNS RFC, but allows for a multicast client to join the group, receiving all multicast network
    ///   traffic. This is useful where listening for all mDNS traffic is of interest, but because another mDNS process may have
    ///   already taken the known port, 5353. Query responses will come from and to the standard UDP socket with a random port,
    ///   multicast traffic will come from the multicast socket. This will create two sockets.
    OneShotJoin,
    /// The querier operates under the OneShot semantics, but also joins the multicast group. (servers)
    ///
    /// Not defined in the RFC, allows for a passive listener to receive all mDNS traffic.
    Passive,
}

impl MdnsQueryType {
    /// This will be sending packets, i.e. a standard UDP socket will be created
    pub fn sender(self) -> bool {
        match self {
            Self::Passive => false,
            Self::OneShot | Self::OneShotJoin => true,
            Self::Continuous => true,
        }
    }

    /// Returns true if this process can bind to *:5353
    pub fn bind_on_5353(self) -> bool {
        match self {
            Self::OneShot | Self::OneShotJoin | Self::Passive => false,
            Self::Continuous => true,
        }
    }

    /// Returns true if this mDNS client should join, listen, on the multicast address
    pub fn join_multicast(self) -> bool {
        match self {
            Self::OneShot => false,
            Self::Continuous | Self::OneShotJoin | Self::Passive => true,
        }
    }
}
