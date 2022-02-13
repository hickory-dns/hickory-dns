# Overview

Trust-DNS Recursor is a library which implements recursive resolution for DNS.

This library can be used to perform DNS resolution beginning with a set of root (hints) authorities. It does not require any

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

The current minimum rustc version for this project is `1.54`

## Versioning

Trust-DNS does it's best job to follow semver. Trust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Trust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Trust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
