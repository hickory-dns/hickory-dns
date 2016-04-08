# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.5.3 2016-04-07
### Fixed
- [Linux TCP server mio issues](https://github.com/bluejekyll/trust-dns/issues/9)

### Changed
- combined the TCP client and server handlers
- reusing buffer in TCP handler between send and receive (performance)

## 0.5.2 2016-04-04
### Changed
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
