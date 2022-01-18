# Overview

Trust-DNS Resolver is a library which implements the DNS resolver using the Trust-DNS Proto library.

This library contains implementations for IPv4 (A) and IPv6 (AAAA) resolution, more features are in the works. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The Trust-DNS [project](https://github.com/bluejekyll/trust-dns) contains other libraries for DNS: a [client library](https://crates.io/crates/trust-dns-client) for raw protocol usage, a [server library](https://crates.io/crates/trust-dns-server) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/trust-dns-rustls) and [native-tls](https://crates.io/crates/trust-dns-native-tls).

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
- DNS over HTTPS (currently only supports `rustls`)

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
let address = response.iter().next().expect("no addresses returned!");
if address.is_ipv4() {
    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
} else {
    assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
}
```

## DNS-over-TLS and DNS-over-HTTPS

DoT and DoH are supported. This is accomplished through the use of one of `native-tls`, `openssl`, or `rustls` (only `rustls` is currently supported for DoH). The Resolver requires only requires valid DoT or DoH resolvers being registered in order to be used.

To use with the `Client`, the `TlsClientConnection` or `HttpsClientConnection` should be used. Similarly, to use with the tokio `AsyncClient` the `TlsClientStream` or `HttpsClientStream` should be used. ClientAuth, mTLS, is currently not supported, there are some issues still being worked on. TLS is useful for Server authentication and connection privacy.

To enable DoT one of the features `dns-over-native-tls`, `dns-over-openssl`, or `dns-over-rustls` must be enabled, `dns-over-https-rustls` is used for DoH.

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

## DNSSec status

Currently the root key is hardcoded into the system. This gives validation of
 DNSKEY and DS records back to the root. NSEC is implemented, but not NSEC3.
 Because caching is not yet enabled, it has been noticed that some DNS servers
 appear to rate limit the connections, validating RRSIG records back to the root
 can require a significant number of additional queries for those records.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, one of the features `dnssec-openssl` or `dnssec-rustls` must be enabled.

## Testing the resolver via CLI with resolve

Useful for testing trust-dns-resolver and it's features via an independent CLI.

```shell
$ cargo install --bin resolve trust-dns-util
```

### example

```shell
$ resolve www.example.com.
Querying for www.example.com. A from udp:8.8.8.8:53, tcp:8.8.8.8:53, udp:8.8.4.4:53, tcp:8.8.4.4:53, udp:[2001:4860:4860::8888]:53, tcp:[2001:4860:4860::8888]:53, udp:[2001:4860:4860::8844]:53, tcp:[2001:4860:4860::8844]:53
Success for query name: www.example.com. type: A class: IN
        www.example.com. 21063 IN A 93.184.216.34
```

## Minimum Rust Version

The current minimum rustc version for this project is `1.54`

## Versioning

Trust-DNS does its best job to follow semver. Trust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Trust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Trust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
