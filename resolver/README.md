# Overview

TRust-DNS Resolver is a library which implements the DNS resolver over the TRust-DNS Client library.

This library contains implementations for IPv4 (A) and IPv6 (AAAA) resolution, more features are in the works. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The TRust-DNS [project](https://github.com/bluejekyll/trust-dns) contains other libraries for DNS: a [client library](https://crates.io/crates/trust-dns) for raw protocol usage, a [server library](https://crates.io/crates/trust-dns-server) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/trust-dns-rustls) and [native-tls](https://crates.io/crates/trust-dns-native-tls).

## Features

- Various IPv4 and IPv6 lookup strategies
- `/etc/resolv.conf` based configuration on Unix/Posix systems
- NameServer pools with performance based priority usage
- Caching of query results
- *TBD* NXDOMAIN caching (negative caching)
- DNSSec validation
- Generic Record Type Lookup (the Client can be used in the interim)
- *TBD* TLS integration

## Example

```rust
use std::net::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

// Construct a new Resolver with default configuration options
let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

// On Unix/Posix systems, this will read the /etc/resolv.conf
// let mut resolver = Resolver::from_system_conf().unwrap();

// Lookup the IP addresses associated with a name.
let mut response = resolver.lookup_ip("www.example.com.").unwrap();

// There can be many addresses associated with the name,
//  this can return IPv4 and/or IPv6 addresses
let address = response.next().expect("no addresses returned!");
if address.is_ipv4() {
    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
} else {
    assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
}
```

## Versioning

TRust-DNS does it's best job to follow semver. TRust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that TRust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. TRust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.