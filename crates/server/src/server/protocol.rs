// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt;

/// For tracking purposes of inbound requests, which protocol was used
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum Protocol {
    /// User Datagram Protocol, the default for all DNS requests
    Udp,
    /// Transmission Control Protocol, used in DNS primarily for large responses (avoids truncation) and AXFR/IXFR
    Tcp,
    /// Transport Layer Security over TCP, for establishing a privacy, DoT (similar to DoH)
    Tls,
    /// Datagram Transport Layer Security over UDP
    Dtls,
    /// HTTP over TLS, DNS over HTTPS, aka DoH (similar to DoT)
    Https,
    /// Quic, DNS over Quic, aka DoQ (similar to DoH)
    Quic,
    /// HTTP over Quic, DNS over HTTP/3, aka DoH3 (similar to DoH)
    H3,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let s = match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Dtls => "DTLS",
            Self::Https => "HTTPS",
            Self::Quic => "QUIC",
            Self::H3 => "H3",
        };

        f.write_str(s)
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}
