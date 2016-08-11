# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## unreleased
### Fixed
- Randomized ports for client connections and message ids, #23

### Changed
- Cleaned up the Server implementation to isolate connection handlers

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
