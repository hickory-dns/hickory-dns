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

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
