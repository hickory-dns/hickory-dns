[![minimum rustc: 1.67](https://img.shields.io/badge/minimum%20rustc-1.67-green?logo=rust)](https://www.whatrustisit.com)
[![Build Status](https://github.com/hickory-dns/hickory-dns/workflows/test/badge.svg?branch=main)](https://github.com/hickory-dns/hickory-dns/actions?query=workflow%3Atest)
[![codecov](https://codecov.io/gh/hickory-dns/hickory-dns/branch/main/graph/badge.svg)](https://codecov.io/gh/hickory-dns/hickory-dns)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE-APACHE)
[![Discord](https://img.shields.io/discord/590067103822774272.svg)](https://discord.gg/89nxE4n)

<div class="oranda-hide">

![Hickory DNS](logo.png)

# Hickory DNS

</div>

A Rust based DNS client, server, and Resolver, built to be safe and secure from the
ground up.

This repo consists of multiple crates:

| Library       | Description                                                                                                                                                                                                                                                                                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Hickory DNS** | [![](https://img.shields.io/crates/v/hickory-dns.svg)](https://crates.io/crates/hickory-dns) Binaries for running a DNS authoritative server.                                                                                                                                                                                                  |
| **Proto**     | [![](https://img.shields.io/crates/v/hickory-proto.svg)](https://crates.io/crates/hickory-proto) [![hickory-proto](https://docs.rs/hickory-proto/badge.svg)](https://docs.rs/hickory-proto) Raw DNS library, exposes an unstable API and only for use by the other Hickory DNS libraries, not intended for end-user use.           |
| **Client**    | [![](https://img.shields.io/crates/v/hickory-client.svg)](https://crates.io/crates/hickory-client) [![hickory-client](https://docs.rs/hickory-client/badge.svg)](https://docs.rs/hickory-client) Used for sending `query`, `update`, and `notify` messages directly to a DNS server.                                             |
| **Server**    | [![](https://img.shields.io/crates/v/hickory-server.svg)](https://crates.io/crates/hickory-server) [![hickory-server](https://docs.rs/hickory-server/badge.svg)](https://docs.rs/hickory-server) Use to host DNS records, this also has a `hickory-dns` binary for running in a daemon form.                                       |
| **Resolver**  | [![](https://img.shields.io/crates/v/hickory-resolver.svg)](https://crates.io/crates/hickory-resolver) [![hickory-resolver](https://docs.rs/hickory-resolver/badge.svg)](https://docs.rs/hickory-resolver) Utilizes the client library to perform DNS resolution. Can be used in place of the standard OS resolution facilities. |

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

## Resolver

The Hickory DNS Resolver is a native Rust implementation for stub resolution in Rust applications. The Resolver supports many common query patterns, all of which can be configured when creating the Resolver. It is capable of using system configuration on Unix and Windows. On Windows there is a known issue that relates to a large set of interfaces being registered for use, so might require ignoring the system configuration.

The Resolver will properly follow CNAME chains as well as SRV record lookups. There is a long term plan to make the Resolver capable of fully recursive queries, but that's not currently possible.

## Client

The Hickory DNS Client is intended to be used for operating against a DNS server directly. It can be used for verifying records or updating records for servers that support SIG0 and dynamic update. The Client is also capable of validating DNSSEC. As of now NSEC3 validation is not yet supported, though NSEC is. There are two interfaces that can be used, the async/await compatible AsyncClient and a blocking Client for ease of use. Today, Tokio is required for the executor Runtime.

### Unique client side implementations

These are standards supported by the DNS protocol. The client implements them
as high level interfaces, which is a bit more rare.

| Feature                                                                                                                       | Description                                           |
| ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| [SyncDnssecClient](https://docs.rs/hickory-client/latest/hickory_client/client/struct.SyncDnssecClient.html)              | DNSSEC validation                                     |
| [create](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.create)                     | atomic create of a record, with authenticated request |
| [append](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.append)                     | verify existence of a record and append to it         |
| [compare_and_swap](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.compare_and_swap) | atomic (depends on server) compare and swap           |
| [delete_by_rdata](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_by_rdata)   | delete a specific record                              |
| [delete_rrset](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_rrset)         | delete an entire record set                           |
| [delete_all](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_all)             | delete all records sets with a given name             |
| [notify](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.notify)                     | notify server that it should reload a zone            |

## Server

The server code is complete, the daemon supports IPv4 and IPv6, UDP and TCP.
There currently is no way to limit TCP and AXFR operations, so it is still not
recommended to put into production as TCP can be used to DOS the service.
Zone file parsing is complete and supported. There is currently no forking
option, and the server is not yet threaded (although it is implemented with
async IO, so threading may not be a huge benefit). There is still a lot of work
to do before a server can be trusted with this externally. Running it behind a
firewall on a private network would be safe.

Zone signing support is complete, to insert a key store a pem encoded rsa file
in the same directory as the initial zone file with the `.key` suffix. _Note_:
this must be only readable by the current user. If one is not present one will
be created and written to the correct location. This also acts as the initial
key for dynamic update SIG(0) validation. To get the public key, the `DNSKEY`
record for the zone can be queried. This is needed to provide to other
upstream servers to create the `DS` key. Dynamic DNS is also complete,
if enabled, a journal file will be stored next to the zone file with the
`jrnl` suffix. _Note_: if the key is changed or updated, it is currently the
operators responsibility to remove the only public key from the zone, this
allows for the `DNSKEY` to exist for some unspecified period of time during
key rotation. Rotating the key currently is not available online and requires
a restart of the server process.

### DNS-over-TLS and DNS-over-HTTPS on the Server

Support of TLS on the Server is managed through a pkcs12 der file. The documentation is captured in the example test config file, [example.toml](https://github.com/hickory-dns/hickory-dns/blob/main/tests/test-data/test_configs/example.toml). A registered certificate to the server can be pinned to the Client with the `add_ca()` method. Alternatively, as the client uses the rust-native-tls library, it should work with certificate signed by any standard CA.

## DNS-over-TLS and DNS-over-HTTPS

DoT and DoH are supported. This is accomplished through the use of one of `native-tls`, `openssl`, or `rustls` (only `rustls` is currently supported for DoH). The Resolver requires valid DoT or DoH resolvers being registered in order to be used.

To use with the `Client`, the `TlsClientConnection` or `HttpsClientConnection` should be used. Similarly, to use with the tokio `AsyncClient` the `TlsClientStream` or `HttpsClientStream` should be used. ClientAuth, mTLS, is currently not supported, there are some issues still being worked on. TLS is useful for Server authentication and connection privacy.

To enable DoT one of the features `dns-over-native-tls`, `dns-over-openssl`, or `dns-over-rustls` must be enabled, `dns-over-https-rustls` is used for DoH.

## DNSSEC status

Currently the root key is hardcoded into the system. This gives validation of
DNSKEY and DS records back to the root. NSEC is implemented, but not NSEC3.
Because caching is not yet enabled, it has been noticed that some DNS servers
appear to rate limit the connections, validating RRSIG records back to the root
can require a significant number of additional queries for those records.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, one of the features `dnssec-openssl` or `dnssec-ring` must be enabled.

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

- [RFC 5155](https://tools.ietf.org/html/rfc5155): DNSSEC Hashed Authenticated Denial of Existence
- [DNSCrypt](https://dnscrypt.org): Trusted DNS queries
- [S/MIME](https://tools.ietf.org/html/draft-ietf-dane-smime-09): Domain Names For S/MIME

# Usage

This assumes that you have [Rust](https://www.rust-lang.org) stable installed. These
presume that the hickory-dns repos have already been synced to the local system:

    git clone https://github.com/hickory-dns/hickory-dns.git
    cd hickory-dns

## Prerequisites

### Minimum Rust Version

- The current minimum rustc version for this project is `1.67`
- OpenSSL development libraries (optional in client and resolver, min version 1.0.2)

### Mac OS X: using homebrew

```
  brew install openssl
  export OPENSSL_INCLUDE_DIR=`brew --prefix openssl`/include
  export OPENSSL_LIB_DIR=`brew --prefix openssl`/lib
```

### Debian-based (includes Ubuntu & Raspbian): using apt-get

```
  # note for openssl that a minimum version of 1.0.2 is required for TLS,
  #  if this is an issue, TLS can be disabled (on the client), see below.
  $ apt-get install openssl
  $ apt-get install libssl-dev pkg-config
```

## Testing

Hickory DNS uses `just` for build workflow management. While running `cargo test` at the project root will work, this is not exhaustive. Install `just` with `cargo install just`.

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

  Hickory DNS has many features, each individual feature can be tested in dependently, see individual crates for all their features, here is a not necessarily up to date list: `dns-over-rustls`, `dns-over-https-rustls`, `dns-over-native-tls`, `dns-over-openssl`, `dns-dnssec-openssl`, `dns-dnssec-openssl`, `dns-dnssec-ring`, `mdns`. Each feature can be tested with itself as the task target for `just`:

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

## Running

Warning: Hickory DNS is still under development, running in production is not
recommended. The server is currently only single-threaded, it is non-blocking
so this should allow it to work with most internal loads.

- Verify the version

```shell
./target/release/hickory-dns --version
```

- Get help

```shell
./target/release/hickory-dns --help
```

- Launch `hickory-dns` server with test config

You may want not passing the `-p` parameter will run on default DNS ports. For the tls features, there are also port options for those, see `hickory-dns --help`

```shell
./target/release/hickory-dns -c ./tests/test-data/test_configs/example.toml -z ./tests/test-data/test_configs/ -p 24141
```

- Query the just launched server with `dig`

```shell
dig @127.0.0.1 -p 24141 www.example.com
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

## Using as a dependency and custom features

The Client has a few features which can be disabled for different reasons when embedding in other software.

- `dnssec-openssl`
  It is a default feature, so default-features will need to be set to false (this will disable all other default features in hickory-dns). Until there are other crypto libraries supported, this will also disable DNSSEC validation. The functions will still exist, but will always return errors on validation. The below example line will disable all default features and enable OpenSSL, remove `"openssl"` to remove the dependency on OpenSSL.

- `dnssec-ring`
  Ring support can be used for RSA and ED25519 DNSSEC validation.

- `dns-over-native-tls`
  Uses `native-tls` for DNS-over-TLS implementation, only supported in client and resolver, not server.

- `dns-over-openssl`
  Uses `openssl` for DNS-over-TLS implementation supported in server and client, resolver does not have default CA chains.

- `dns-over-rustls`
  Uses `rustls` for DNS-over-TLS implementation, only supported in client and resolver, not server. This is the best option where a pure Rust toolchain is desired. Supported in client, resolver, and server.

- `dns-over-https-rustls`
  Uses `rustls` for DNS-over-HTTPS (and DNS-over-TLS will be enabled) implementation, only supported in client, resolver, and server. This is the best option where a pure Rust toolchain is desired.

- `mdns` _EXPERIMENTAL_
  Enables the experimental mDNS features as well as DNS-SD. This currently has known issues.

Using custom features in dependencies:

```
[dependencies]
  ...
hickory-dns = { version = "*", default-features = false, features = ["dnssec-openssl"] }
```

Using custom features during build:

```console
$> cargo build --release --features dns-over-rustls
...
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
