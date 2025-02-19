# Overview

Hickory DNS Server is a library which implements the zone authoritory functionality.

This library contains basic implementations for DNS zone hosting. It is capable of performing signing all records in the zone for server DNSSEC RRSIG records associated with all records in a zone. There is also a `hickory-dns` binary that can be generated from the library with `cargo install hickory-dns`. Dynamic updates are supported via `SIG0` (an mTLS authentication method is under development).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-server](https://crates.io/crates/hickory-server), from `0.24` and onward, for prior versions see [trust-dns-server](https://crates.io/crates/trust-dns-server).

## Status

The server code is complete, the daemon supports IPv4 and IPv6, UDP and TCP.
There currently is no way to limit TCP and AXFR operations, so it is still not
recommended to put into production as TCP can be used to DOS the service.
Zone file parsing is complete and supported. There is currently no forking
option, and the server is not yet threaded (although it is implemented with
async IO, so threading may not be a huge benefit). There is still a lot of work
to do before a server can be trusted with this externally. Running it behind a
firewall on a private network would be safe.

Zone signing support is complete, to insert a key store a pem encoded rsa file
in the same directory as the initial zone file with the `.key` suffix. _Note_:
this must be only readable by the current user. If one is not present one will
be created and written to the correct location. This also acts as the initial
key for dynamic update SIG(0) validation. To get the public key, the `DNSKEY`
record for the zone can be queried. This is needed to provide to other
upstream servers to create the `DS` key. Dynamic DNS is also complete,
if enabled, a journal file will be stored next to the zone file with the
`jrnl` suffix. _Note_: if the key is changed or updated, it is currently the
operators responsibility to remove the only public key from the zone, this
allows for the `DNSKEY` to exist for some unspecified period of time during
key rotation. Rotating the key while online is not currently supported, so
a restart of the server process is required.

## Features

- Dynamic Update with sqlite journaling backend (SIG0)
- DNSSEC online signing (NSEC and NSEC3)
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
- Maybe NSEC5 support

## Minimum Rust Version

The current minimum rustc version for this project is `1.70`

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
