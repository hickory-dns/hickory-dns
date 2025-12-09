# Overview

`hickory-resolver` is a safe and secure DNS stub resolver library intended to be a high-level library
for DNS record resolution.

It can be configured to use the system resolver configuration and will properly follow CNAME chains
as well as SRV record lookups.

## Features

- Various IPv4 and IPv6 lookup strategies
- `/etc/resolv.conf` based configuration on Unix/Posix systems
- NameServer pools with performance based priority usage
- Caching of query results
- NxDomain/NoData caching (negative caching)
- DNSSEC validation
- Generic Record Type Lookup
- CNAME chain resolution

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

* `system-config` (enabled by default) - support using the system recursive resolver configuration.
* `tokio` (enabled by default) - support for the Tokio async runtime.
* `serde` - enable serde serialization support.
* `toml` - enable support for TOML serialization.
* `rustls-platform-verifier` (enabled by default) - use the system verifier for TLS with
  [rustls-platform-verifier].
* `webpki-roots` - use the [webpki-roots] crate for TLS certificate verification.
* `metrics` - support exposing metrics using the [`metrics`] crate.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots
[`metrics`]: https://crates.io/crates/metrics

## `resolve` command line tool

A simple `resove` command-line utility that uses `hickory-resolver` can be installed
to test the crate functionality:

```shell
cargo install --bin resolve hickory-util
```

### example

```shell
$ resolve www.example.com.
Querying for www.example.com. A from udp:8.8.8.8:53, tcp:8.8.8.8:53, udp:8.8.4.4:53, tcp:8.8.4.4:53, udp:[2001:4860:4860::8888]:53, tcp:[2001:4860:4860::8888]:53, udp:[2001:4860:4860::8844]:53, tcp:[2001:4860:4860::8844]:53
Success for query name: www.example.com. type: A class: IN
        www.example.com. 21063 IN A 93.184.215.14
```
