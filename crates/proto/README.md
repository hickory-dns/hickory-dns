# Overview

Trust-DNS Proto is the foundational DNS protocol library and implementation for Trust-DNS. Unless you want to manipulate the DNS packets directly, it is likely not the library you want. Please see Trust-DNS [Resolver](https://crates.io/crates/trust-dns-resolver), [Client](https://crates.io/crates/trust-dns-client), or [Server](https://crates.io/crates/trust-dns-server) for higher level interfaces.

## Minimum Rust Version

The current minimum rustc version for this project is `1.59`

## Versioning

Trust-DNS does it's best job to follow semver. Trust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Trust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Trust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
