# Overview

Hickory DNS Resolver is a library which implements the DNS resolver using the Hickory DNS Proto library.

This library contains implementations for IPv4 (A) and IPv6 (AAAA) resolution, more features are in the works. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The Hickory DNS [project](https://github.com/hickory-dns/hickory-dns) contains other libraries for DNS: a [client library](https://crates.io/crates/hickory-client) for raw protocol usage, a [server library](https://crates.io/crates/hickory-server) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/hickory-dns-rustls) and [native-tls](https://crates.io/crates/hickory-dns-native-tls).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-resolver](https://crates.io/crates/hickory-resolver), from `0.24` and onward, for prior versions see [trust-dns-resolver](https://crates.io/crates/trust-dns-resolver).

## Features

- Various IPv4 and IPv6 lookup strategies
- `/etc/resolv.conf` based configuration on Unix/Posix systems
- NameServer pools with performance based priority usage
- Caching of query results
- NxDomain/NoData caching (negative caching)
- DNSSEC validation
- Generic Record Type Lookup
- CNAME chain resolution
- DNS over TLS (utilizing `native-tls`, `rustls`, and `openssl`; `native-tls` or `rustls` are recommended)
- DNS over HTTPS (currently only supports `rustls`)

## Example

```rust
use std::net::*;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::config::*;

// Construct a new Resolver with default configuration options
let resolver = Resolver::new(
    ResolverConfig::default(),
    ResolverOpts::default(),
    TokioConnectionProvider::default(),
);

// On Unix/Posix systems, this will read the /etc/resolv.conf
// let resolver = Resolver::from_system_conf(TokioConnectionProvider::default()).unwrap();

// Lookup the IP addresses associated with a name.
let response = resolver.lookup_ip("www.example.com.").await.unwrap();

// There can be many addresses associated with the name,
//  this can return IPv4 and/or IPv6 addresses
let address = response.iter().next().expect("no addresses returned!");
if address.is_ipv4() {
    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
} else {
    assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)));
}
```

## DNS-over-TLS and DNS-over-HTTPS

DoT and DoH are supported. This is accomplished through the use of one of `native-tls`, `openssl`, or `rustls` (only `rustls` is currently supported for DoH). The Resolver requires valid DoT or DoH resolvers being registered in order to be used.

Client authentication/mTLS is currently not supported, there are some issues
still being worked on. TLS is useful for Server authentication and connection
privacy.

To enable DoT, one of the features `dns-over-native-tls`, `dns-over-openssl`, or
`dns-over-rustls` must be enabled. `dns-over-https-rustls` is used for DoH.

### Example

Enable the TLS library through the dependency on `hickory-resolver`:

```toml
hickory-resolver = { version = "*", features = ["dns-over-rustls"] }
```

A default TLS configuration is available for Cloudflare's `1.1.1.1` DNS service (Quad9 as well):

```rust
// Construct a new Resolver with default configuration options
let resolver = Resolver::new(
    ResolverConfig::cloudflare_tls(),
    ResolverOpts::default(),
    TokioConnectionProvider::default(),
);

/// see example above...
```

## DNSSEC status

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

To enable DNSSEC, one of the features `dnssec-openssl` or `dnssec-ring` must be
enabled.

## Testing the resolver via CLI with resolve

This independent CLI is useful for testing hickory-resolver and its features.

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

## Minimum Rust Version

The current minimum rustc version for this project is `1.70`

## Versioning

Hickory DNS does its best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
