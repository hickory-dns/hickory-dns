# Overview

> [!WARNING]
> This library is experimental

`hickory-recursor` is a safe and secure DNS recursive resolver library with DNSSEC support.

This library can be used to perform DNS resolution beginning with a set of root (hints) authorities. 
It does not require an upstream recursive resolver to find records in DNS.

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

* `serde` - enable serde serialization support.
* `metrics` - support exposing metrics using the [`metrics`] crate.
* `backtrace` - enable error backtrace collection.

[`metrics`]: https://crates.io/crates/metrics
