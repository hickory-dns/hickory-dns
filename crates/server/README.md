# Overview

Trust-DNS Server is a library which implements the zone authoritory functionality.

This library contains basic implementations for DNS zone hosting. It is capable of performing signing all records in the zone for server DNSSec RRSIG records associated with all records in a zone. There is also a `named` binary that can be generated from the library with `cargo install trust-dns-server`. Dynamic updates are supported via `SIG0` (an mTLS authentication method is under development).

## Versioning

Trust-DNS does it's best job to follow semver. Trust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Trust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Trust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.