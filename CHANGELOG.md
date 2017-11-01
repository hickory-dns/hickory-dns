# Change Log: TRust-DNS

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.13.0

### Added

- TRust-DNS Proto crate to separate server management from base operations #222
- TRust-DNS Util crate for dnssec management tools (@briansmith)
- Integration tests for Server to validate all supported DNSSec key types
- Common features `dnssec-ring`, `dnssec-openssl`, and `dnssec` across all crates
- Clarified `tls` feature with `tls-openssl`, and `tls` in server

### Changed

- DNSKEY is now self-signed
- Internal API changes to `client` calling into `proto` for actual implementations
- Large refactoring of internal APIs to more cleanly support \*ring\* and OpenSSL features (@briansmith)
- `ClientHandle::send` moved to `trust_dns_proto::DnsHandle::send` (internal API)
- Many interfaces moved from `client::ClientStreamHandle` to `trust_dns_proto::DnsStreamHandle`
- `Message::sign` has been renamed and change to the more general method `Message::finalize`
- Some `io::Error`s have been converted to `trust_dns_proto::ProtoError`
- `SyncClient` and `SecureSyncClient` are now `Send + Sync` #245

### Fixed

- Server: signing issues when loading from persistence
- Server: When SupportedAlgorithms (rfc6975) not supplied default to returning all signatures #215

### Removed

- Removed the `NativeTls` and `OpenSSL` `ClientConnection` variants, used the Rustls impls or the tokio based `TlsClientStream` instead. This was required for `SyncClient` being `Send + Sync`
- Server: no longer auto-generate keys on startup #218
- All deprecated APIs removed from -proto #262
- Server: removed deprated RSA config loading options, see reference test cargo.tomls #276 (@briansmith)

## 0.12.0

### Fixed

- Server was not properly signing zone after fresh start

### Added

- RSA and ECDSA validation with *ring* for DNSSec, removes dependency on openssl (@briansmith)
- `lookup` to `ClientHandle`, simpler form with `Query`
- `query` to `Query` for ease of Query creation

### Changed

- Large celanup of signing and verification paths in DNSSec (@briansmith)
- *breaking* changed `TrustAnchor::insert_trust_anchor` to more safely consume `PublicKey` rather than `Vec<u8>` 

## 0.11.2

(README.md documentation changes for crates.io)

## 0.11.1

### Changed

- Updates to `Name::is_fqdn` for more accuracy (@rushmorem)

### Added

- per project Readme.md for crates.io

## 0.11.0

### Added

- `Name::FromStr` for simpler parsing, specify trailing `.` for FQDN
- `Name::append_label` for clearer usage while appending labels to a Name
- `Name::append_name` for clearer usage while appending one name to another
- `Name::append_domain` alias for append_name and marking as FQDN

### Changed

- *breaking* all `&mut self` methods on `Name` deprecated as unsafe, Name labels are now immutable.
- *breaking* All `ClientHandle` traits now take `&Handle` instead of `Handle` (@rushmorem)
- *warning* `Name` now tracks if it is a fully qualified domain name, slightly changes name parsing rules, allowing `www.example.com` without the trailing `.`, which means that FQDN names are not enforced.

### Removed

- *deprecated* `Name::with_labels` see `Name::from_labels`
- *deprecated* `Name::append` wasn't clean, see `Name::append_name`
- *deprecated* `Name::add_label` exposed internal data structure, see `Name::append_label`
- *deprecated* `Name::label` unclear usage/name, see `Name::append_label`
- *deprecated* `Name::prepend_label` exposed internal data structure, unclear usage *no replacement*
- *deprecated* `Record::add_name` unclear usage *no replacement*

## 0.10.5

### Added

- Library documentation, examples for client query and update

### Changed

- ServerFuture now Accepts generic RequestHandler (@Antti)

## 0.10.4

### Added

- Allow more options with Key and KeyUsage
- Initial Resolver implementation

### Fixed

- NSEC coverage bitmap overflow in nightly
- Name::zone_of panic (@SAPikachu)

## 0.10.3

### Fixed

- Proper TCP connection timeout
- Fixed signature format of ECDSA (@SAPikachu) #141

## 0.10.2

### Fixed

- Fixed format of ED25519 keys (@briansmith) #129

### Changed

- Revamped signer and keypair to better deal with public key (possible breaking change)
- Upgraded *ring* to 0.9.x series, requires pkcs8 for key storage
- Dropped support for dangerous private key byte access (possible breaking change)
- Upgraded tokio-rustls and rustls dependencies to support *ring* updates

### Added

- PublicKey and Verifier for verifying with zero copy from KEY and DNSKEY (possible breaking change)
- Pkcs8 as a supported KeyFormat for storage (possible breaking change)

## 0.10.1

### Added

- Added `From<IpAddr>` for Name (reverse DNS) #105
- AppVeyor support #103
- rustls client tls support (separate crate)
- full support for KEY RR in client
- compatibility tests with BIND for SIG0 updates
- Added full implementation of KEY type

### Changed

- Updated TLS documentation, added more elsewhere, docs required; fixes #102
- Upgraded tokio-core and moved to tokio-io
- *Important* Some `Server` types have been migrated to [RFC#344](https://github.com/aturon/rfcs/blob/conventions-galore/active/0000-conventions-galore.md#gettersetter-apis) style. `get_field()` -> `field()`; `field()` -> `set_field()`
- Moved native-tls client impl to separate crate
- Defaulted to OpenSSL for tls implementation

### Fixed

- key_tag calculation for DNSKEY and KEY now correct #118 (@jannic)
- SIG0 signing fixed to match RFC and BIND #120 (@jannic)

## 0.10.0

### Changed

- *Important* Possible breaking API change, the original Client has been renamed.

In an attempt to reduce the overhead of managing the project. The original
Client has now been revamped to essentially be a synchronous Client over the
ClientFuture implementation. The ClientFuture has proven to be a more stable
and reliable implementation. It was attempted to make the move seamless,
but two new types were introduced, `SyncClient` and `SecureSyncClient`, which
are both synchronous implementations of the old Client function interfaces.
Please read those docs on those new types and the Client trait.

- When EDNS option is present, return only the digest understood matching RRSETs
- All code reformatted with rustfmt
- *Important* breaking change, all `Record` and associated types have been migrated to [RFC#344](https://github.com/aturon/rfcs/blob/conventions-galore/active/0000-conventions-galore.md#gettersetter-apis) style. `get_field()` -> `field()`; `field()` -> `set_field()`

### Removed

- *Important* The original Server implementation was removed entirely.

Please use the ServerFuture implementation from now on. Sorry for the inconvenience,
but this is necessary to make sure that the software remains at a high quality
and there is no easy way to migrate the original Server to use ServerFuture.

### Added

- Initial support for ECDSAP256SHA256, ECDSAP384SHA384 and ED25519 (client and server)
- additional config options for keys to named, see `tests/named_test_configs/example.toml`
- Added DNS over TLS support, RFC 7858, #38
- Added native-tls with support for macOS and Linux (DNS over TLS)
- matrixed tests for all features to Travis

## 0.9.3

### Changed

- updated to rust-openssl 0.9.x series
- restructured dnssec code to better support alternate key formats

## 0.9.2

### Changed

- mio_client is now an optional feature in favor of the futures-rs ClientFuture

## 0.9.1

### Changed

- OpenSSL is now an optional feature for the client

## 0.9.0

### Added

- new ServerFuture tokio and futures based server, #61
- UdpStream & TcpSteam to support stream of messages with src address
- TimeoutStream to wrap TcpStreams to help guard against malicious clients
- Added Notify support to ClientFuture
- Added IntoRecordSet and conversion impls for RecordSet and Record

### Changed

- Split Server and Client into separate crates, #43
- Moved many integration tests to `tests` from `src`, #52
- Migrated all handles to new futures::sync::mpsc impls
- Modified all requisite client methods for IntoRecordSet.
- All client methods now support multiple records per query, update, notify and delete

### Fixed

- Flush TcpStream after fully sending Message
- Recognize no bytes read as closed TcpStream

## 0.8.1

### Fixed

- Fix build on rustc 1.11, #66

## 0.8.0

### Added

- SecureClientHandle, for future based DNSSec validation.
- ClientFuture, futures based client implementation, #32

### Fixed

- Randomized ports for client connections and message ids, #23
- OpCode::From for u8 removed, added OpCode::from_u8(), #36
- Fix for named startup related to ipv6, #56

### Changed

- Upgraded OpenSSL to 0.8.* #50
- Cleaned up the Server implementation to isolate connection handlers
- Deprecated old Client will possibly remove in the future

## 0.7.3 2016-08-12

### Fixed

- Issue #27: label case sensitivity revisited for RRSIG signing, RFC 6840
- TCP reregister on would-block errors

## 0.7.2 2016-08-10

### Fixed

- Issue #28: RRSIG validation of wildcards, label length > wildcard length

## 0.7.1 2016-08-09

### Fixed

- Issue #27: remove implicit case conversion of labels (fixes NSEC validation)

## 0.7.0 2016-06-20

### Added

- Added recovery from journal to named startup
- SQLite journal for dynamic update persistence
- Private Key generation during startup, for dnssec zones
- Read private key from filesystem during start and registers to zone

### Changed

- Removed many of the unwraps in named binary
- Reworked all errors to use error-chain
- Adjusted interface for Signer to use duration
- All `#[cfg(ftest)]` tests now `#[ignore]`

### Fixed

- TXT record case sensitivity

## 0.6.0 2016-06-01

### Added

- Documentation on all modules, and many standard RFC types
- Authority zone signing now complete, still need to load/save private keys
- DNSKEYs auto inserted for added private keys
- New mocked network client tests, to verify zone signing
- NSEC record creation for zone, with tests
- SIG0 validation for Authentication on for dynamic updates
- Client CQADDD operations, delete_by_rdata, delete_rrset, delete_all
- Client compare_and_swap operation... atomics are here!

### Fixed

- Added loop on TCP accept requests
- Added loop on UDP reads
- Upgraded to mio 0.5.1 for some bug fixes
- Not returning RRSIGs with SOA records on authoritative answers

### Changed

- Internal representation of record sets now a full data structure
- Better rrset keys for fewer clones
- Removed many excessive clones (should make requests even faster)
- Cleaned up authority upsert and lookup interfaces
- All authorities default to IN DNSCLASS now (none others currently supported)
- Cleaned up the Signer interface to support zone signing
- Simplified RData variant implementations
- Improved ENDS and SIG0 parsing on Message deserialization

## 0.5.3 2016-04-07

### Fixed

- [Linux TCP server mio issues](https://github.com/bluejekyll/trust-dns/issues/9)

### Changed

- combined the TCP client and server handlers
- reusing buffer in TCP handler between send and receive (performance)

## 0.5.2 2016-04-04

### Changed

- updated mio to 0.5.0
- updated chrono to 0.2.21
- updated docopt to 0.6.78
- updated log to 0.3.5
- updated openssl to 0.7.8
- updated openssl-sys to 0.7.8
- updated rustc-serialize to 0.3.18
- updated toml to 0.1.28

## 0.5.1 2016-03-30

### Added

- NSEC3 resolver validation
- data-ecoding as a dependency (base32hex)
- trust-dns banner on boot of server

### Changed

- Changed the bin.rs to named.rs, more accurate, allow for other binaries

## 0.5.0 2016-03-22

### Added

- Updated rust-openssl to 0.7.8 which include new RSA creation bindings
- NSEC resolver validation
- NSEC3 parsing support
- DNSSec validation of RRSIG and DNSKEY records back to root cert
- Integration with OpenSSL (depends on fork until rust-openssl 0.7.6+ is cut)
- Binary serialization and deserialization of all DNSSec RFC4034 record types
- EDNS support
- Coveralls support added
- Partial implementation of SIG0 support for dynamic update
- SRV record support

### Changed

- Dual licensed with MIT (and Apache 2.0)
- Abstracted Client over TCP and UDP for common implementation of queries

### Fixed

- Binary Serialization and Deserialization of NSEC3
- AXFR SOA ordering
- Travis build failing

### Deprecated

- See updated trust_dns::client::Client API

## 0.4.0 2015-10-17

### Added

- Added AXFR support
- Dynamic update support

### Fixed

- Name pointer support

## 0.3.1 2015-10-04

### Fixed

- Removed buffer clone during label pointer decoding (speed/memory)
- Removed a lot of unnecessary clones, heavier use of Rc
- Binary server bugs (fully functional)

## 0.3.0 2015-09-27

### Added

- Master zone files support BIND time formats, e.g. #h#d
- Toml config file support (not compatible with BIND)

## 0.2.1 2015-09-17

### Added

- Functional tests to verify against other DNS servers

### Changed

- mio replaced std::net operators

## 0.2.0 2015-09-07

### Added

- Server support with catalog and tests for example.com
- Parsing example rfc1035 master file
- new lexer for master zone files with simplified FSM
- Travis CI testing support
- Supported Client with operational query
- Writers for Record Data
- All RFC1035 fields parsing!
- label parsing with UTF8 support
- DNS Class and RecordType enums

### Fixed

- Crates.io keywords, etc.

### Changed

- Cleaned up binary encoders and decoders with objects

## 0.1.0 2015-08-07

### Added

- Started parsing resource records
- Initial Commit!
