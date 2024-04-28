# Overview

Hickory DNS provides a binary for hosting or forwarding DNS zones.

This a named implementation for DNS zone hosting. It is capable of performing signing all records in the zone for server DNSSEC RRSIG records associated with all records in a zone. There is also a `hickory-dns` binary that can be generated from the library with `cargo install hickory-dns`. Dynamic updates are supported via `SIG0` (an mTLS authentication method is under development).

**NOTICE** This project was rebranded fromt Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-dns](https://crates.io/crates/hickory-dns), from `0.24` and onward, for prior versions see [trust-dns](https://crates.io/crates/trust-dns).

## Features

- Dynamic Update with sqlite journaling backend (SIG0)
- DNSSEC online signing (NSEC not NSEC3)
- DNS over TLS (DoT)
- DNS over HTTPS/2 (DoH)
- DNS over HTTPS/3 (DoH3)
- DNS over Quic (DoQ)
- Forwarding stub resolver
- ANAME resolution, for zone mapping aliass to A and AAAA records
- Additionals section generation for aliasing record types

## DNS-over-TLS and DNS-over-HTTPS

Support of TLS on the Server is managed through a pkcs12 der file. The documentation is captured in the example test config file, [example.toml](https://github.com/hickory-dns/hickory-dns/blob/main/tests/test-data/test_configs/example.toml). A registered certificate to the server can be pinned to the Client with the `add_ca()` method. Alternatively, as the client uses the rust-native-tls library, it should work with certificate signed by any standard CA.

DoT and DoH are supported. This is accomplished through the use of one of `native-tls`, `openssl`, or `rustls` (only `rustls` is currently supported for DoH). The Resolver requires valid DoT or DoH resolvers being registered in order to be used.

To use with the `Client`, the `TlsClientConnection` or `HttpsClientConnection` should be used. Similarly, to use with the tokio `AsyncClient` the `TlsClientStream` or `HttpsClientStream` should be used. ClientAuth, mTLS, is currently not supported, there are some issues still being worked on. TLS is useful for Server authentication and connection privacy.

To enable DoT one of the features `dns-over-native-tls`, `dns-over-openssl`, or `dns-over-rustls` must be enabled, `dns-over-https-rustls` is used for DoH.

## DNSSEC status

Currently the root key is hardcoded into the system. This gives validation of
DNSKEY and DS records back to the root. NSEC is implemented, but not NSEC3.
Because caching is not yet enabled, it has been noticed that some DNS servers
appear to rate limit the connections, validating RRSIG records back to the root
can require a significant number of additional queries for those records.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, one of the features `dnssec-openssl` or `dnssec-ring` must be enabled.

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
