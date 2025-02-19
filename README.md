[![minimum rustc: 1.70](https://img.shields.io/badge/minimum%20rustc-1.70-green?logo=rust)](https://www.whatrustisit.com)
[![Build Status](https://github.com/hickory-dns/hickory-dns/workflows/test/badge.svg?branch=main)](https://github.com/hickory-dns/hickory-dns/actions?query=workflow%3Atest)
[![codecov](https://codecov.io/gh/hickory-dns/hickory-dns/branch/main/graph/badge.svg)](https://codecov.io/gh/hickory-dns/hickory-dns)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE-APACHE)
[![Discord](https://img.shields.io/discord/590067103822774272.svg)](https://discord.gg/89nxE4n)

<div class="oranda-hide">

![Hickory DNS](logo.png)

# Hickory DNS

</div>

A Rust based DNS client, server, and resolver, built to be safe and secure from the
ground up.

This repo consists of multiple crates:

| Library         | Description                                                                                                                                                                                                                                                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Hickory DNS**](bin/)             | [![](https://img.shields.io/crates/v/hickory-dns.svg)](https://crates.io/crates/hickory-dns) Provides the `hickory-dns` binary for running a DNS server.                                                                                                                                                                         |
| [**Proto**](crates/proto/)          | [![](https://img.shields.io/crates/v/hickory-proto.svg)](https://crates.io/crates/hickory-proto) [![hickory-proto](https://docs.rs/hickory-proto/badge.svg)](https://docs.rs/hickory-proto) Low-level DNS library, including message encoding/decoding and DNS transports.                                                       |
| [**Client**](crates/client/)        | [![](https://img.shields.io/crates/v/hickory-client.svg)](https://crates.io/crates/hickory-client) [![hickory-client](https://docs.rs/hickory-client/badge.svg)](https://docs.rs/hickory-client) Used for sending `query`, `update`, and `notify` messages directly to a DNS server.                                             |
| [**Server**](crates/server/)        | [![](https://img.shields.io/crates/v/hickory-server.svg)](https://crates.io/crates/hickory-server) [![hickory-server](https://docs.rs/hickory-server/badge.svg)](https://docs.rs/hickory-server) Used to build DNS servers. The `hickory-dns` binary makes use of this library.                                                  |
| [**Resolver**](crates/resolver/)    | [![](https://img.shields.io/crates/v/hickory-resolver.svg)](https://crates.io/crates/hickory-resolver) [![hickory-resolver](https://docs.rs/hickory-resolver/badge.svg)](https://docs.rs/hickory-resolver) Utilizes the client library to perform DNS resolution. Can be used in place of the standard OS resolution facilities. |
| [**Recursor**](crates/recursor/)    | [![](https://img.shields.io/crates/v/hickory-recursor.svg)](https://crates.io/crates/hickory-recursor) [![hickory-recursor](https://docs.rs/hickory-recursor/badge.svg)](https://docs.rs/hickory-recursor) Performs recursive DNS resolution, looking up records from their authoritative name servers.                          |

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo.

# Goals

- Build a safe and secure DNS server and client with modern features.
- No panics, all code is guarded
- Use only safe Rust, and avoid all panics with proper Error handling
- Use only stable Rust
- Protect against DDOS attacks (to a degree)
- Support options for Global Load Balancing functions
- Make it dead simple to operate

# Status

## DNSSEC status

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, enable the `dnssec-ring` feature.

## RFCs implemented

- [RFC 8499](https://tools.ietf.org/html/rfc8499): No more master/slave, in honor of [Juneteenth](https://en.wikipedia.org/wiki/Juneteenth)

### Basic operations

- [RFC 1035](https://tools.ietf.org/html/rfc1035): Base DNS spec (see the Resolver for caching)
- [RFC 2308](https://tools.ietf.org/html/rfc2308): Negative Caching of DNS Queries (see the Resolver)
- [RFC 2782](https://tools.ietf.org/html/rfc2782): Service location
- [RFC 3596](https://tools.ietf.org/html/rfc3596): IPv6
- [RFC 6891](https://tools.ietf.org/html/rfc6891): Extension Mechanisms for DNS
- [RFC 6761](https://tools.ietf.org/html/rfc6761): Special-Use Domain Names (resolver)
- [RFC 6762](https://tools.ietf.org/html/rfc6762): mDNS Multicast DNS (experimental feature: `mdns`)
- [RFC 6763](https://tools.ietf.org/html/rfc6763): DNS-SD Service Discovery (experimental feature: `mdns`)
- [RFC ANAME](https://tools.ietf.org/html/draft-ietf-dnsop-aname-02): Address-specific DNS aliases (`ANAME`)

### Update operations

- [RFC 2136](https://tools.ietf.org/html/rfc2136): Dynamic Update
- [RFC 7477](https://tools.ietf.org/html/rfc7477): Child-to-Parent Synchronization in DNS

### Secure DNS operations

- [RFC 2931](https://datatracker.ietf.org/doc/html/rfc2931): SIG(0)
- [RFC 3007](https://tools.ietf.org/html/rfc3007): Secure Dynamic Update
- [RFC 4034](https://tools.ietf.org/html/rfc4034): DNSSEC Resource Records
- [RFC 4035](https://tools.ietf.org/html/rfc4035): Protocol Modifications for DNSSEC
- [RFC 4509](https://tools.ietf.org/html/rfc4509): SHA-256 in DNSSEC Delegation Signer
- [RFC 5155](https://tools.ietf.org/html/rfc5155): DNSSEC Hashed Authenticated Denial of Existence
- [RFC 5702](https://tools.ietf.org/html/rfc5702): SHA-2 Algorithms with RSA in DNSKEY and RRSIG for DNSSEC
- [RFC 6844](https://tools.ietf.org/html/rfc6844): DNS Certification Authority Authorization (CAA) Resource Record
- [RFC 6698](https://tools.ietf.org/html/rfc6698): The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
- [RFC 6840](https://tools.ietf.org/html/rfc6840): Clarifications and Implementation Notes for DNSSEC
- [RFC 6844](https://tools.ietf.org/html/rfc6844): DNS Certification Authority Authorization Resource Record
- [RFC 6944](https://tools.ietf.org/html/rfc6944): DNSKEY Algorithm Implementation Status
- [RFC 6975](https://tools.ietf.org/html/rfc6975): Signaling Cryptographic Algorithm Understanding
- [RFC 7858](https://tools.ietf.org/html/rfc7858): DNS over TLS (feature: `dns-over-rustls`, `dns-over-native-tls`, or `dns-over-openssl`)
- [RFC DoH](https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-14): DNS over HTTPS, DoH (feature: `dns-over-https-rustls`)

## RFCs in progress or not yet implemented

### Basic operations

- [RFC 2317](https://tools.ietf.org/html/rfc2317): Classless IN-ADDR.ARPA delegation

### Update operations

- [RFC 1995](https://tools.ietf.org/html/rfc1995): Incremental Zone Transfer
- [RFC 1996](https://tools.ietf.org/html/rfc1996): Notify secondaries of update
- [Update Leases](https://tools.ietf.org/html/draft-sekar-dns-ul-01): Dynamic DNS Update Leases
- [Long-Lived Queries](https://tools.ietf.org/html/draft-sekar-dns-llq-01): Notify with bells

### Secure DNS operations

- [DNSCrypt](https://dnscrypt.org): Trusted DNS queries
- [S/MIME](https://tools.ietf.org/html/draft-ietf-dane-smime-09): Domain Names For S/MIME

## Minimum Rust Version

- The current minimum rustc version for this project is `1.70`

## Testing

Hickory DNS uses `just` for build workflow management. While running `cargo test` at the project root will work, this is not exhaustive. Install `just` with `cargo install just`. A few of the `just` recipes require [`cargo-workspaces`](https://github.com/pksunkara/cargo-workspaces) to be installed, a plugin to optimize the workflow around cargo workspaces. Install the plugin with `cargo install cargo-workspaces`.

- Default tests

  These are good for running on local systems. They will create sockets for
  local tests, but will not attempt to access remote systems. Tests can also
  be run from the crate directory, i.e. `client` or `server` and `cargo test`

```shell
just default
```

- Default feature tests

  Hickory DNS has many features, to quickly test with them or without, there are three targets supported, `default`, `no-default-features`, `all-features`:

```shell
just all-features
```

- Individual feature tests

  Hickory DNS has many features, each individual feature can be tested
  independently. See individual crates for all their features, here is a not
  necessarily up to date list: `dns-over-rustls`, `dns-over-https-rustls`,
  `dns-over-native-tls`, `dns-over-openssl`, `dns-dnssec-openssl`,
  `dns-dnssec-openssl`, `dns-dnssec-ring`, `mdns`. Each feature can be tested
  with itself as the task target for `just`:

```shell
just dns-over-https-rustls
```

- Benchmarks

  Waiting on benchmarks to stabilize in mainline Rust.

## Building

- Production build, from the `hickory-dns` base dir, to get all features, just pass the `--all-features` flag.

```shell
cargo build --release -p hickory-dns
```

## Using the hickory-resolver CLI

Available in `0.20`

```shell
cargo install --bin resolve hickory-util
```

Or from source, in the hickory-dns directory

```shell
cargo install --bin resolve --path util
```

example:

```shell
$ resolve www.example.com.
Querying for www.example.com. A from udp:8.8.8.8:53, tcp:8.8.8.8:53, udp:8.8.4.4:53, tcp:8.8.4.4:53, udp:[2001:4860:4860::8888]:53, tcp:[2001:4860:4860::8888]:53, udp:[2001:4860:4860::8844]:53, tcp:[2001:4860:4860::8844]:53
Success for query name: www.example.com. type: A class: IN
        www.example.com. 21063 IN A 93.184.215.14
```

## FAQ

- Why are you building another DNS server?

      Because of all the security advisories out there for BIND.

  Using Rust semantics it should be possible to develop a high performance and
  safe DNS Server that is more resilient to attacks.

- What is the MSRV (minimum stable Rust version) policy?

      Hickory DNS will work to support backward compatibility with three Rust versions.

  For example, if `1.50` is the current release, then the MSRV will be `1.47`. The
  version is only increased as necessary, so it's possible that the MSRV is older
  than this policy states. Additionally, the MSRV is only supported for the `no-default-features`
  build due to it being an intractable issue of trying to enforce this policy on dependencies.

## Community

For live discussions beyond this repository, please see this [Discord](https://discord.gg/89nxE4n).

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
