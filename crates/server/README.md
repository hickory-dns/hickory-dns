# Overview

`hickory-server` is a library for integrating safe and secure DNS servers into
an async Tokio application. It supports a variety of protocol features
(DNSSEC, TSIG, SIG(0), DoT, DoQ, DoH). Servers can be operated in an authoritative
role, or as a forwarding resolver, stub resolver, or a recursive resolver
(experimental).

See the [`hickory-dns`] binary crate for a complete application built using
`hickory-server`.

[`hickory-dns`]: ../../bin/

## Features

- Dynamic Update with sqlite journaling backend (SIG0, TSIG)
- DNSSEC online signing (NSEC and NSEC3)
- DNS over TLS (DoT)
- DNS over QUIC (DoQ)
- DNS over HTTPS (DoH)
- DNS over HTTP/3 (DoH3)
- Forwarding stub resolver
- Recursive resolver (experimental)
- ANAME resolution, for zone mapping aliass to A and AAAA records
- Additionals section generation for aliasing record types
