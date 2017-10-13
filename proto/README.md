# Overview

TRust-DNS Proto is the foundational DNS protocol library and implementation for TRust-DNS. It is not expected to be used directly. Please see TRust-DNS [Resolver](https://crates.io/crates/trust-dns-resolver), [Client](https://crates.io/crates/trust-dns), or [Server](https://crates.io/crates/trust-dns-server) for higher level interfaces.

*WARNING* The Proto crate is designed as an internal layer in the TRust-DNS ecosystem, it will change potentially in breaking ways, and should not generally be used directly. Please see the Resolver, Client or Server for more stable interfaces.

## Versioning

TRust-DNS does it's best job to follow semver. TRust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that TRust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. TRust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
