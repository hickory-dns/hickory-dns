# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Added
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
