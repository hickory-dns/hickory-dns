# Overview

Hickory DNS Server is a library which implements the zone authoritory functionality.

This library contains basic implementations for DNS zone hosting. It is capable of performing signing all records in the zone for server DNSSEC RRSIG records associated with all records in a zone. There is also a `hickory-dns` binary that can be generated from the library with `cargo install hickory-dns`. Dynamic updates are supported via `SIG0` (an mTLS authentication method is under development).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-server](https://crates.io/crates/hickory-server), from `0.24` and onward, for prior versions see [trust-dns-server](https://crates.io/crates/trust-dns-server).

## Features

- Dynamic Update with sqlite journaling backend (SIG0)
- DNSSEC online signing (NSEC not NSEC3)
- DNS over TLS (DoT)
- DNS over HTTPS (DoH)
- Forwarding stub resolver
- ANAME resolution, for zone mapping aliass to A and AAAA records
- Additionals section generation for aliasing record types

## Future goals

- Distributed dynamic DNS updates, with consensus
- mTLS based authorization for Dynamic Updates
- Online NSEC creation for queries
- Full hint based resolving
- Maybe NSEC3 and/or NSEC5 support

## Minimum Rust Version

The current minimum rustc version for this project is `1.67`

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
