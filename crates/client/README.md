# Overview

This crate provides `hickory-client`, a safe and secure DNS client library with a 
variety of protocol features (DNSSEC, SIG(0), DoT, DoQ, DoH). It can be used to 
connect to and query DNS servers asynchronously using the Tokio runtime.

This library contains basic implementations for DNS record serialization, and communication. 
It is capable of performing `query`, `update`, and `notify` operations. 
`update` has been proven to be compatible with `BIND9` and `SIG0` signed records for updates. 
It is built on top of the [tokio](https://tokio.rs) runtime and can be integrated into other
systems using the tokio and futures libraries. 

See also the [`hickory-resolver`] and [`hickory-recursor`] crates for other client roles.

[`hickory-resolver`]: ../resolver
[`hickory-recursor`]: ../recursor

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

In order to use DNSSEC you must enable a cargo feature corresponding to your desired 
cryptography provider:

* `dnssec-aws-lc-rs`
* `dnssec-ring`

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

## Other crate features

* `serde` - enable serde serialization support.
* `backtrace` - enable error backtrace collection.
* `mdns` (experimental) - enable experimental mDNS support.
* `rustls-platform-verifier` - use the system verifier for TLS with
  [rustls-platform-verifier].
* `webpki-roots` - use the [webpki-roots] crate for TLS certificate verification.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots
