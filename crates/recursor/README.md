# Overview

Hickory DNS Recursor is a library which implements recursive resolution for DNS. This is currently experimental, test coverage is low and full scope of tests haven't been determined yet.

This library can be used to perform DNS resolution beginning with a set of root (hints) authorities. It does not require an upstream recursive resolver to find records in DNS.

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-recursor](https://crates.io/crates/hickory-recursor), from `0.24` and onward, for prior versions see [trust-dns-recursor](https://crates.io/crates/trust-dns-recursor).

## Minimum Rust Version

The current minimum rustc version for this project is `1.70`

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
