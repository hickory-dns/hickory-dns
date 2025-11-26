# Overview

This crate provides a `hickory-dns` application, a safe and secure DNS server with a variety of 
protocol features (DNSSEC, TSIG, SIG(0), DoT, DoQ, DoH). It can be operated as an authoritative
DNS server, forwarding resolver, stub resolver, or a recursive resolver (experimental).
Zone data can be managed in-memory, with flat files, or with an SQLite database.

## Features

- Dynamic Update with sqlite journaling backend (SIG0)
- DNSSEC online signing (with NSEC and NSEC3)
- Forwarding stub resolver
- ANAME resolution, for zone mapping aliases to A and AAAA records
- Additionals section generation for aliasing record types

## Cryptography provider

Features requiring cryptography require selecting a specific cryptography 
provider. See the [project README] for more information.

[project README]: ../README.md#Cryptography-provider

## Protocol support

The following DNS protocols are optionally supported:

* DNS over TLS (DoT)
* DNS over HTTP/2 (DoH)
* DNS over QUIC (DoQ)
* DNS over HTTP/3 (DoH3)

In order to use these optional protocols you must enable a cargo feature
corresponding to your desired cryptography provider:

* DoT: `tls-aws-lc-rs` or `tls-ring`
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

When using dynamic DNS, zones will be automatically resigned on any record updates.

## Other crate features

* `sqlite` (enabled by default) - support maintaining zone data in a SQLite database.
  Required for dynamic DNS support.
* `blocklist` - support configuring allow/deny blocklists.
* `recursor` - enable experimental support for recursive resolution.
* `resolver` (enabled by default) - enable forwarding zones to another resolver.
* `rustls-platform-verifier` (enabled by default) - use the system verifier for TLS with
   [rustls-platform-verifier].
* `webpki-roots` - use the [webpki-roots] crate for TLS certificate verification.
* `prometheus-metrics` - enable exposing [Prometheus] metrics for scraping.
* `ascii-art` (enabled by default) - print project logo at start.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots
[Prometheus]: https://prometheus.io/

## Running

Warning: Hickory DNS is still under development, running in production is not
recommended.

- Building

```shell
cargo build --release --bin hickory-dns
```

- Verify the version

```shell
./target/release/hickory-dns --version
```

- Get help

```shell
./target/release/hickory-dns --help
```

- Launch `hickory-dns` server with test config

Note that if the `-p` parameter is not passed, the server will run on default
DNS ports. There are separate port options for DoT and DoH servers, see
`hickory-dns --help`

```shell
./target/release/hickory-dns -c ./tests/test-data/test_configs/example.toml -z ./tests/test-data/test_configs/ -p 24141
```

- Query the just launched server with `dig`

```shell
dig @127.0.0.1 -p 24141 www.example.com
```
