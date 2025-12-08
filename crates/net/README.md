# Overview

`hickory-net` provides network protocol implementations for DNS message transport.
This is a support library used by the other higher-level Hickory DNS crates.

For higher-level interfaces, refer to the [`hickory-server`] and [`hickory-resolver`]
library crates instead.

[`hickory-server`]: ../server
[`hickory-resolver`]: ../resolver

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

## Other crate features

* `tokio` - support for the Tokio async runtime.
* `serde` - enable serde serialization support.
* `mdns` (experimental) - enable experimental mDNS support.
