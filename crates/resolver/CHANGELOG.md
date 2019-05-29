# Change Log: Trust-DNS Resolver

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.11.1

- disables the `socket2/reuseport` feature except when `mdns` is enabled

## 0.11

### Fixed

- Ignore UDP responses not from target src address #629 #630 #631 (@aep)
- Improved NSEC validation of responses #697

### Added

- New option to execute queries concurrently, default is 2 #615
- Lookup::record_iter for listing all records returned in request #674
- NAPTR record data (no additional record processing support) #731

### Changed

- Added option to distrust Nameservers on SERVFAIL responses, continue resolution #613
- *breaking* Record::from_rdata no longer requires RecordType parameter #674
- LRU cache is now based on Query rather than just name #674

## 0.10.2

### Fixed

- all optional dependencies updated #640

## 0.10.1

### Fixed

- UDP Sockets not being properly closed in timeout scenarios #635

## 0.10

### Fixed

- Fix two separate integer overflows from substractions #585 (@oherrala)
- strictly enforce name and label lengths during label parsing #584
- enforce that only prior labels are used in label expansion, decompression #578 (@oherrala)
- CAA now properly performs case-incesitive compares #587 (@oherrala)
- overhauled rdata parsers with Restrict type to reduce potential of overflowing operations #586
- Propagate TTLs for NXDOMAIN responses #485 (@hawkw)
- LookupIpFuture implementation to be proper in regards to loop control #480 (@hawkw)
- max query depth tracking in Resolver #469

### Changed

- Wrap types in Restrict and force validation before usage from streams #586
- Delays all connections until actual use #566
- Relax parsing rules for CAA issuer keys and values #517
- `ResolverFuture` renamed to `AsyncResolver` #487 (@hawkw)
- *breaking* `AsyncResolver::new` returns a tuple of an `AsyncResolver` and a future that drives DNS lookups in the background #487 (@hawkw)
- *breaking* All `AsyncResolver` lookup methods return `BackgroundLookup<T>` rather than `T` #487 (@hawkw)
- *breaking* Migrated from error_chain to Failure #474 (@silwol)
- improve truncation to always return records #497

### Added

- updated root trust-anchor to include new `20326` RSA root ksk
- DNS over HTTPS support #520

## 0.9.1

### Fixes

- Fixes the MAX TTL being outside the bounds of 32bit systems, reduces max to 1 day #528

## 0.9

### Added

- DNS-over-TLS configurations (requires one of `dns-over-native-tls` or `dns-over-rustls` features) #396
- Experimental DNS-SD, service discovery (RFC 6763, `mdns` feature required) #363
- Experimental mDNS, multicast DNS, known issues persist (RFC 6762, `mdns` feature required) #337
- Exposed TTLs on `Lookup` objects @hawkw #444
- Added global resolver example #460

### Changed

- Use tokio-timer (part of tokio upgrade) @justinlatimer #411
- Backtrace now optional @briansmith #416
- Upgrade to tokio-tcp (tokio upgrade) @Keruspe #426
- Upgrade to tokio-udp (tokio upgrade) @Keruspe #427
- Upgrade to tokio-executor (tokio upgrade) @Keruspe and @justinlatimer #438
- Always reattempt nameserver reconnections regardless of time #457
- Defaulted type parameter for LookupFuture, removed InnerLookupFuture #459

### Fixed

- BinEncoder panic on record sets of extreme sizes #352
- Panic when oneshot channel receiver goes away #356
- Incorrect IPv6 configuration for Google nameservers #358
- Properly yield on failure to acquire lock #372
- Correct order of search list with ndots variable #410
- Send (Sync where applicable) enforced on all DnsHandle::send and other interfaces #460
- Properly track max query depth as a `task_local` not `thread_local` #460, #469
- IPv4 like name resolution in lookup_ip with search order #467

### Removed

- usage of tokio-core::Core @Keruspe #446

## 0.8.1

### Changed

- Make read_system_conf() function public #338 (@oherrala)
- Hosts map was not properly reference counted #342

### Fixed

- Panic in edge case of label compression #341 (@SAPikachu)
- Fix `localhost` lookup and no longer panic on no names #343

## 0.8.0

### Changed

- Updated `trust-dns-proto` to `0.3`, which brings in better `Name` and `Label` impls
- Dropped LALRPOP `resolv.conf` parser in favor of the `resolv-conf` #335 (@cssivision & @little-dude)
- Improved message serialization #311 (@little-dude)
- Many serialization improvements #317
- Dependencies updated #334 (@oherrala)

### Added

- `Name` and `Label` now support idna, punycode, see `Name::from_str`
- Clippy added to build #304! (@neosilky)
- `from_system_conf` on now supported on Windows 32bit targets (previously just 64bit) #313 (@liranringel)

### Fixed

- octal escapes fixed in `Name` parsing #330
- `NULL` record type incorrectly valued at `0` to proper `10` #329 (@jannic)

## 0.7.0

### Changed

- Resolver no longer depends on Client
- *breaking* Resolver no longer returns io:Errors, use `From<ResolveError>` for `io::Error`
- Resolver is now `Send`
- DNSSec now disabled by default in Resolver, see `dnssec-ring` or `dnssec-openssl` features #268
- CNAME chaining was cleaned up #271 (@briansmith)
- On hostname parsing to IpAddr, return without lookup #302 (@cssivision)
- Change default `LookupIpStrategy` from `Ipv4AndIpv6` to `Ipv4thenIpv6` #301 (@cssivision)

### Added

- ResolveError and associated types

### Fixed

- Cleaned up CNAME chained lookups, better TTL enforcement, etc #298

## 0.6.0

### Changed

- Split UDP and TCP into different NS pools, prefer UDP lookups first
- On truncated UDP responses, promote to TCP for resolution

### Added

- 64bit Windows support for reading DNS configuration! (@liranringel)
- CNAME chain resolution (where CNAME results are not returned in the same query)
- Resolution prefers `/etc/hosts` before querying (@cssivision)

## 0.5.0

### Changed

- *breaking* `LookupIp` now returns an iterator over owned data (IpAddr is Copy + Clone ref not necessary)
- *breaking* `Resolver::lookup` will now return an Err on NxDomain and NoData responses
- rewrote much of the caching and lookup functionality for generic RecordType lookups
- removed &mut from resolver fn interfaces, make it easier to use

### Added

- Generic record type lookup
- reverse_lookup for IP to Name lookups
- ipv4_lookup for looking up *only* ipv4 (lookup_ip has options for dual-stack)
- ipv6_lookup for looking up *only* ipv6 (lookup_ip has options for dual-stack)
- mx_lookup for querying mail exchanges
- srv_lookup for service records and also a specialized form for ease of use lookup_service
- txt_lookup for text record lookups

## 0.4.0

### Removed

- *breaking* impl `Iterator` removed from `LookupIp` result type, see `LookupIp::iter` for replacement

### Added

- Support for DNSSec validation
- LRU Cache

## 0.3.0

### Added

- `options attempts:N` aka `ResolverOpts::attempts` support, aka retries
- Google IPv6 nameservers as defaults for `ResolverConfig::default`
- support for domain name search in `ResolverConfig` and `LookupIpFuture`
- support for search names in `ResolverConfig` and `LookupIpFuture`
- `LookupIpFuture` type alias to `LookupIpFuture<NameServerPool>` *compatibility*

### Changed

- *breaking* `LookupIpFuture` renamed to `LookupIpFuture`
- *breaking* `LookupIpFuture` now takes a generic parameter, generally `<NameServerPool>`

## 0.2.0

### Added

- ipv6 parallel lookup
- multiple ipv4 and ipv6 lookup strategies
- library documentation examples
- test coverage for resolver

## 0.1.0

### Added

- Initial release of the Trust-DNS Resolver
