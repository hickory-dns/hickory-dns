// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Multicast protocol related components for DNS

mod mdns_client_stream;
mod mdns_stream;

pub use self::mdns_client_stream::MdnsClientStream;
pub use self::mdns_stream::{MdnsStream, MDNS_IPV4, MDNS_IPV6};

/// See [rfc6762](https://tools.ietf.org/html/rfc6762#section-5) details on these different types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdnsQueryType {
    /// The querier using this socket will only perform standard DNS queries over multicast. (clients only)
    ///
    /// Effectively treats mDNS as essentially no different than any other DNS query; one request followed by one response.
    OneShot,
    /// The querier is fully compliant with [rfc6762](https://tools.ietf.org/html/rfc6762#section-5). (servers, clients optional)
    ///
    /// mDNS capable clients will sent messages with many queries, and they will expect many responses.
    Continuous,
}

impl MdnsQueryType {
    /// Returns true if the MdnsQueryType is OneShot, false otherwise
    pub fn is_one_shot(&self) -> bool {
        *self == MdnsQueryType::OneShot
    }
}