# Overview

Hickory DNS Proto is the foundational DNS protocol library and implementation for Hickory DNS. Unless you want to manipulate the DNS packets directly, it is likely not the library you want. Please see Hickory DNS [Resolver](https://crates.io/crates/hickory-resolver), [Client](https://crates.io/crates/hickory-client), or [Server](https://crates.io/crates/hickory-server) for higher level interfaces.

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-proto](https://crates.io/crates/hickory-proto), from `0.24` and onward, for prior versions see [trust-dns-proto](https://crates.io/crates/trust-dns-proto).

## Minimum Rust Version

The current minimum rustc version for this project is `1.70`

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
