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

## Cryptography provider

Features requiring cryptography require selecting a specific cryptography
provider. See the [project README] for more information.

[project README]: ../../README.md#Cryptography-provider

## Protocol support

The following DNS protocols are optionally supported:

* DNS over TLS (DoT)
* DNS over HTTP/2 (DoH)
* DNS over QUIC (DoQ)
* DNS over HTTP/3 (DoH3)

In order to use these optional protocols you must enable a cargo feature
corresponding to your desired cryptography provider:

* DoT: `tls-aws-lc-rs` or `tls-ring`.
* DoH: `https-aws-lc-rs` or `https-ring`
* DoQ: `quic-aws-lc-rs` or `quic-ring`
* DoH3: `h3-aws-lc-rs` or `h3-ring`

## DNSSEC

In order to use DNSSEC you must enable a cargo feature corresponding to your
desired cryptography provider:

* `dnssec-aws-lc-rs`
* `dnssec-ring`

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

## Other crate features

* `resolver` - support for DNS query resolving.
* `recursor` (experimental) - support for recursive resolution.
* `sqlite` - support maintaining zone data in a SQLite database. Required for dynamic DNS support.
* `blocklist` - support configuring allow/deny blocklists.
* `toml` - support for TOML configuration.
* `metrics` - support exposing metrics using the [`metrics`] crate.
* `rustls-platform-verifier` - use the system verifier for TLS with
  [rustls-platform-verifier].
* `webpki-roots` - use the [webpki-roots] crate for TLS certificate verification.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots
[`metrics`]: https://crates.io/crates/metrics
