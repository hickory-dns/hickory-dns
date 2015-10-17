# trust-dns [![Build Status](https://travis-ci.org/bluejekyll/trust-dns.svg?branch=master)](https://travis-ci.org/bluejekyll/trust-dns)
A Rust based DNS client and server, built to be safe and secure from the
ground up.

# Goals

- Build a safe and secure DNS server and client with modern features.
- No panics, all code is guarded
- Use only safe Rust, and avoid all panics with proper Error handling
- Use only stable Rust
- Protect against DDOS attacks (to a degree)
- Support options for Global Load Balancing functions
- Make it dead simple to operate

# Status:

WARNING!!! Under active development!

The client now supports timeouts (thanks mio!). Currently hardcoded to 5 seconds,
 I'll make this configurable if people ask for that, but this allows me to move on.

The server code is complete, the daemon currently only supports IPv4. Master file
parsing is complete and supported.

## RFC's implemented

- RFC 1035: Base DNS spec (partial, caching not yet supported)
  https://tools.ietf.org/html/rfc1035
- RFC 3596: IPv6
  https://tools.ietf.org/html/rfc3596
- RFC 2136: Dynamic Update
  https://tools.ietf.org/html/rfc2136

## RFC's in progress or not yet implemented

- RFC 1995: Incremental Zone Transfer
  https://tools.ietf.org/html/rfc1995
- RFC 1996: Notify slaves of update
  https://tools.ietf.org/html/rfc1996
- RFC 2782: Service location
  https://tools.ietf.org/html/rfc2782
- RFC 3007: Secure Dynamic Update
  https://tools.ietf.org/html/rfc3007
- RFC 6891: Extension Mechanisms for DNS
  https://tools.ietf.org/html/rfc6891
- RFC 4034: DNSSEC Resource Records
  https://tools.ietf.org/html/rfc4034
- DNSCrypt
  https://dnscrypt.org/
- Dynamic DNS Update Leases
  https://tools.ietf.org/html/draft-sekar-dns-ul-01
- DNS Long-Lived Queries
  http://tools.ietf.org/html/draft-sekar-dns-llq-01

# Usage

TBD

# FAQ

- Why are you building another DNS server?

Because I've gotten tired of seeing the security advisories out there for BIND.
Using Rust semantics it should be possible to develop a high performance and
safe DNS Server that is more resilient to attacks.
