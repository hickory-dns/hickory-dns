# Overview

Hickory DNS provides a binary for hosting or forwarding DNS zones.

This a named implementation for DNS zone hosting, stub resolvers, and recursive
resolvers. It is capable of performing signing all records in the zone for
server DNSSEC RRSIG records associated with all records in a zone. There is also
a `hickory-dns` binary that can be generated from the library with `cargo
install hickory-dns`. Dynamic updates are supported via `SIG0` (an mTLS
authentication method is under development).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-dns](https://crates.io/crates/hickory-dns), from `0.24` and onward, for prior versions see [trust-dns](https://crates.io/crates/trust-dns).

## Features

- Dynamic Update with sqlite journaling backend (SIG0)
- DNSSEC online signing (with NSEC and NSEC3)
- Forwarding stub resolver
- ANAME resolution, for zone mapping aliases to A and AAAA records
- Additionals section generation for aliasing record types

## Optional protocol support

The following DNS protocols are optionally supported:

- Enable `dns-over-rustls` for DNS over TLS (DoT)
- Enable `dns-over-https-rustls` for DNS over HTTP/2 (DoH)
- Enable `dns-over-quic` for DNS over QUIC (DoQ)
- Enable `dns-over-h3` for DNS over HTTP/3 (DoH3)

## DNSSEC status

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, enable the `dnssec-ring` feature.

## Future goals

- Distributed dynamic DNS updates, with consensus
- mTLS based authorization for Dynamic Updates
- Online NSEC creation for queries
- Maybe NSEC5 support

## Running

Warning: Hickory DNS is still under development, running in production is not
recommended.

- Verify the version

```shell
./target/release/hickory-dns --version
```

- Get help

```shell
./target/release/hickory-dns --help
```

- Launch `hickory-dns` server with test config

Note that if the `-p` parameter is not passed, the server will run on default
DNS ports. There are separate port options for DoT and DoH servers, see
`hickory-dns --help`

```shell
./target/release/hickory-dns -c ./tests/test-data/test_configs/example.toml -z ./tests/test-data/test_configs/ -p 24141
```

- Query the just launched server with `dig`

```shell
dig @127.0.0.1 -p 24141 www.example.com
```

## Minimum Rust Version

The current minimum rustc version for this project is `1.70`

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
