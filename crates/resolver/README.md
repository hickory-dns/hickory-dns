# Overview

Trust-DNS Resolver is a library which implements the DNS resolver using the Trust-DNS Proto library.

This library contains implementations for IPv4 (A) and IPv6 (AAAA) resolution, more features are in the works. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The Trust-DNS [project](https://github.com/bluejekyll/trust-dns) contains other libraries for DNS: a [client library](https://crates.io/crates/trust-dns) for raw protocol usage, a [server library](https://crates.io/crates/trust-dns-server) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/trust-dns-rustls) and [native-tls](https://crates.io/crates/trust-dns-native-tls).

## Features

- Various IPv4 and IPv6 lookup strategies
- `/etc/resolv.conf` based configuration on Unix/Posix systems
- NameServer pools with performance based priority usage
- Caching of query results
- NxDomain/NoData caching (negative caching)
- DNSSec validation
- Generic Record Type Lookup
- CNAME chain resolution
- *experimental* mDNS support (enable with `mdns` feature)
- DNS over TLS (utilizing `native-tls`, `rustls`, and `openssl`; `native-tls` or `rustls` are recommended)
- *experimental* DNS over HTTPS (currently only supports `rustls`)

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

## Enabling DNS-over-TLS and DNS-over-HTTPS

**DNS-over-TLS**, DoT, the underlying implementations have been available as addon libraries to the Client and Server, but the configuration is experimental in Trust-DNS Resolver. *WARNING* The author makes no claims on the security and/or privacy guarantees of this implementation.

To use you must compile in support with one of the `dns-over-tls` features. There are three: `dns-over-openssl`, `dns-over-native-tls`, and `dns-over-rustls`. The reason for each is to make the Trust-DNS libraries flexible for different deployments, and/or security concerns. The easiest to use will generally be `dns-over-rustls` which utilizes the native Rust library (a rework of the `boringssl` project), this should compile and be usable on most ARM and x86 platforms. `dns-over-native-tls` will utilize the hosts TLS implementation where available or fallback to `openssl` where not. `dns-over-openssl` will specify that `openssl` should be used (which is a perfect fine option if required). If more than one is specified, the presidence will be in this order (i.e. only one can be used at a time) `dns-over-rustls`, `dns-over-native-tls`, and then `dns-over-openssl`. *NOTICE* the author is not responsible for any choice of library that does not meet security requirements.

**DNS-over-HTTPS**, DoH, currently the only supported TLS library is `rustls`. To enable, us the feature `dns-over-https-rustls`.

### Example

Enable the TLS library through the dependency on `trust-dns-resolver`:

```toml
trust-dns-resolver = { version = "*", features = ["dns-over-rustls"] }
```

A default TLS configuration is available for Cloudflare's `1.1.1.1` DNS service (Quad9 as well):

```rust
// Construct a new Resolver with default configuration options
let mut resolver = Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();

/// see example above...
```

## Versioning

Trust-DNS does its best job to follow semver. Trust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Trust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Trust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
