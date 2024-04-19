# Overview

Hickory DNS Async-Std Resolver is a library which implements the DNS resolver using the Hickory DNS Resolver library.

This library contains implementations for IPv4 (A) and IPv6 (AAAA) resolution, more features are in the works. It is built on top of the [async-std](https://async.rs) async-io project, this allows it to be integrated into other systems using the async-std and futures libraries. The Hickory DNS [project](https://github.com/hickory-dns/hickory-dns) contains other libraries for DNS: a [client library](https://crates.io/crates/hickory-client) for raw protocol usage, a [server library](https://crates.io/crates/hickory-server) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/hickory-dns-rustls) and [native-tls](https://crates.io/crates/hickory-dns-native-tls).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, from `0.24` and onward.

## Features

- Various IPv4 and IPv6 lookup strategies
- `/etc/resolv.conf` based configuration on Unix/Posix systems
- NameServer pools with performance based priority usage
- Caching of query results
- NxDomain/NoData caching (negative caching)
- TBD (in tokio impl): DNSSEC validation
- Generic Record Type Lookup
- CNAME chain resolution
- _experimental_ mDNS support (enable with `mdns` feature)
- TBD (in tokio impl): DNS over TLS (utilizing `native-tls`, `rustls`, and `openssl`; `native-tls` or `rustls` are recommended)
- TBD (in tokio impl): DNS over HTTPS (currently only supports `rustls`)

## Example

```rust
use std::net::*;
use async_std::prelude::*;
use async_std_resolver::{resolver, config};

#[async_std::main]
async fn main() {
  // Construct a new Resolver with default configuration options
  let resolver = resolver(
    config::ResolverConfig::default(),
    config::ResolverOpts::default(),
  ).await;

  // Lookup the IP addresses associated with a name.
  // This returns a future that will lookup the IP addresses, it must be run in the Core to
  //  to get the actual result.
  let mut response = resolver.lookup_ip("www.example.com.").await.unwrap();

  // There can be many addresses associated with the name,
  //  this can return IPv4 and/or IPv6 addresses
  let address = response.iter().next().expect("no addresses returned!");
  if address.is_ipv4() {
    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
  } else {
    assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c)));
  }
}
```

## Minimum Rust Version

The current minimum rustc version for this project is `1.67`

## Versioning

Hickory DNS does its best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
