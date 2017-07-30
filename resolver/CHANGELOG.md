# Change Log: TRust-DNS Resolver

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.3.0 (Unreleased)

### Added

- Added `options attempts:N` aka `ResolverOpts::attempts` support, aka retries
- Added Google IPv6 nameservers as defaults for `ResolverConfig::default`
- Added support for domain name search in `ResolverConfig` and `LookupIpFuture`
- Added support for search names in `ResolverConfig` and `LookupIpFuture`
- Added `LookupIpFuture` type alias to `InnerLookupIpFuture<NameServerPool>` *compatibility*

### Changed

- *breaking* `LookupIpFuture` renamed to `InnerLookupIpFuture`
- *breaking* `InnerLookupIpFuture` now takes a generic parameter, generally `<NameServerPool>`

## 0.2.0

### Added

- ipv6 parallel lookup
- multiple ipv4 and ipv6 lookup strategies
- library documentation examples
- test coverage for resolver

## 0.1.0

### Added

- Initial release of the TRust-DNS Resolver