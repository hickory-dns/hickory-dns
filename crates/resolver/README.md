# Overview

Hickory DNS Resolver is a library which implements the DNS resolver using the Hickory DNS Proto library.

This library contains implementations for IPv4 (A) and IPv6 (AAAA) resolution, more features are in the works. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The Hickory DNS [project](https://github.com/hickory-dns/hickory-dns) contains other libraries for DNS: a [client library](https://crates.io/crates/hickory-client) for raw protocol usage, a [server library](https://crates.io/crates/hickory-server) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/hickory-dns-rustls) and [native-tls](https://crates.io/crates/hickory-dns-native-tls).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-resolver](https://crates.io/crates/hickory-resolver), from `0.24` and onward, for prior versions see [trust-dns-resolver](https://crates.io/crates/trust-dns-resolver).

## Status

The Hickory DNS Resolver is a native Rust implementation for stub resolution in Rust applications. The Resolver supports many common query patterns, all of which can be configured when creating the Resolver. It is capable of using system configuration on Unix and Windows. On Windows there is a known issue that relates to a large set of interfaces being registered for use, so might require ignoring the system configuration.

The Resolver will properly follow CNAME chains as well as SRV record lookups.

## Features

- Various IPv4 and IPv6 lookup strategies
- `/etc/resolv.conf` based configuration on Unix/Posix systems
- NameServer pools with performance based priority usage
- Caching of query results
- NxDomain/NoData caching (negative caching)
- DNSSEC validation
- Generic Record Type Lookup
- CNAME chain resolution

## Optional protocol support

The following DNS protocols are optionally supported:

- Enable `dns-over-rustls` for DNS over TLS (DoT)
- Enable `dns-over-https-rustls` for DNS over HTTP/2 (DoH)
- Enable `dns-over-quic` for DNS over QUIC (DoQ)
- Enable `dns-over-h3` for DNS over HTTP/3 (DoH3)

## Example

```rust
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
let _address = response.iter().next().expect("no addresses returned!");
```

## DNSSEC status

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

To enable DNSSEC, enable the `dnssec-ring` feature.

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
