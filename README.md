# trust-dns
A Rust based DNS server

# Goals

- Build a safe and secure DNS server and client with modern features.
- Use Threads to allow all code to panic! and fail fast, without taking down
the server.
- Protect against DDOS attacks (to a degree)
- Support options for Global Load Balancer functions
- Build in a nice REST interface for managing server?

# Status:

Under active development! Do not attempt to use in any production systems.

# In progress:

- Support original (minus unused) RFC 1035 specification.
All parsers complete.
Todo: Serializers.
Todo: Operations.

- Support DNS Update RFC 2136.
- DNSSEC Resource Records RFC 4034
- DNSSec protocol RFC 4035
- Dynamic DNS Update Leases https://tools.ietf.org/html/draft-sekar-dns-ul-01
- DNS Long-Lived Queries http://tools.ietf.org/html/draft-sekar-dns-llq-01

# FAQ

- Why are you building another DNS server?

Because I've gotten tired of seeing the security advisories out there for BIND.
Using Rust semantics it should be possible to develop a high performance and
safe DNS Server that is more resilient to attacks.
