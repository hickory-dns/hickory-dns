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
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let s = match self {
            Protocol::Udp => "UDP",
            Protocol::Tcp => "TCP",
            Protocol::Tls => "TLS",
            Protocol::Dtls => "DTLS",
            Protocol::Https => "HTTPS",
        };

        f.write_str(s)
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}
