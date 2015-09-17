# trust-dns [![Build Status](https://travis-ci.org/bluejekyll/trust-dns.svg?branch=master)](https://travis-ci.org/bluejekyll/trust-dns)
A Rust based DNS client and server, built to be safe and secure from the
ground up.

# Goals

- Build a safe and secure DNS server and client with modern features.
- Use Threads to allow all code to panic! and fail fast, without taking down
the server.
- Use only safe Rust, and avoid all panics with proper Error handling
- Use only stable Rust
- Protect against DDOS attacks (to a degree)
- Support options for Global Load Balancer functions
- Build in a nice REST interface for managing server?

# Status:

WARNING!!! Under active development! Do not attempt to use in any production systems.

The client now supports timeouts (thanks mio!). Currently hardcoded to 5 seconds, I'll make
this configurable if people ask for that, but this allows me to move on.

The server code is complete, the daemon is currently in progress. Once this is done
the plan is to start self-host trust-dns.org on the trust-dns software.

# Goals:

- Support original (minus unused) RFC 1035 specification. (nearing completion)
- EDNS http://tools.ietf.org/html/rfc2671 (not started)
- Support DNS Update RFC 2136.            (not started)
- DNSSEC Resource Records RFC 4034        (not started)
- DNSSec protocol RFC 4035                (not started)
- DNSCrypt https://dnscrypt.org/          (not started)
- Dynamic DNS Update Leases https://tools.ietf.org/html/draft-sekar-dns-ul-01 (not started)
- DNS Long-Lived Queries http://tools.ietf.org/html/draft-sekar-dns-llq-01    (not started)

# FAQ

- Why are you building another DNS server?

Because I've gotten tired of seeing the security advisories out there for BIND.
Using Rust semantics it should be possible to develop a high performance and
safe DNS Server that is more resilient to attacks.
