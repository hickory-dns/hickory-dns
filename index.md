# TRustDNS
TRustDNS was started to answer a few problems that have been seen in BIND and other standard DNS servers on the internet.
* DNSSec is difficult to manage and is often ignored by many configurations. 
    TRustDNS is designed from the ground up to be easy to use and ensure that DNSSec and other security features are easy to use.
* DynamicDNS should be easy to enable
* Resilient to attacks
    TRustDNS is written in 100% safe [Rust](https://www.rust-lang.org). Rust is a compiled language designed to offer a memory safe programming environment which drastically reduces the risk of data race conditions, memory leaks and unsafe access to uninitialized memory. These are common issues in other languages which can lead to security and availability issues of DNS servers.
* Easy to configure and manage 

# Status
**WARNING!!!** *Under active development! Do not attempt to use in any production systems.*

A note on sockets, this client is only using Rust stable, socket options are
currently feature restricted. This means that the Client is very dangerous to use
at the moment because it will wait forever for a response from the server.

## In progress:

* Support original (minus unused) RFC 1035 specification.
    Client is complete, all requests should work
    Todo: Server...

* EDNS http://tools.ietf.org/html/rfc2671
* Support DNS Update RFC 2136.
* DNSSEC Resource Records RFC 4034
* DNSSec protocol RFC 4035
* Dynamic DNS Update Leases https://tools.ietf.org/html/draft-sekar-dns-ul-01
* DNS Long-Lived Queries http://tools.ietf.org/html/draft-sekar-dns-llq-01

# Authors and Contributors
Benjamin Fry (@bluejekyll) started TRustDNS in 2015, mostly to play with Rust.

# License and Copyright
Copyright is held by Benjamin Fry, the project is license under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0). In order to have the flexibility of changing both the copyright and the license in the future, all code in TRustDNS repository will share this license and copyright.