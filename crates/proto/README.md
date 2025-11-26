# Overview

`hickory-proto` is a safe and secure low-level DNS library. 
This is the foundational DNS protocol library used by the other higher-level Hickory DNS crates.

Unless you want to manipulate the DNS packets directly, it is likely not the library you want.
For higher-level interfaces, refer to the [`hickory-server`], [`hickory-client`],
[`hickory-resolver`] and [`hickory-recursor`] library crates instead.

[`hickory-server`]: ../server
[`hickory-client`]: ../client
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

In order to use DNSSEC you must enable a cargo feature corresponding to your
desired cryptography provider:

* `dnssec-aws-lc-rs`
* `dnssec-ring`

## Other crate features

* `text-parsing` - support for reading text-based zone files.
* `tokio` - support for the Tokio async runtime.
* `serde` - enable serde serialization support.
* `std` - disable for no-std support.
* `no-std-rand` - enables a custom random function backed by a no_std compatible mutex.
* `mdns` (experimental) - enable experimental mDNS support.
* `wasm-bindgen` - support for WASM.
* `backtrace` - enable error backtrace collection.
* `access-control` - enable data structures useful for blocklists and access control.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots
