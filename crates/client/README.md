# Overview

This crate provides `hickory-client`, a safe and secure DNS client library with a 
variety of protocol features (DNSSEC, SIG(0), DoT, DoQ, DoH). It can be used to 
connect to and query DNS servers asynchronously using the Tokio runtime.

This library contains basic implementations for DNS record serialization, and communication. 
It is capable of performing `query`, `update`, and `notify` operations. 
`update` has been proven to be compatible with `BIND9` and `SIG0` signed records for updates. 
It is built on top of the [tokio](https://tokio.rs) runtime and can be integrated into other
systems using the tokio and futures libraries. 

See also the [`hickory-resolver`] and [`hickory-recursor`] crates for other client roles.

[`hickory-resolver`]: ../resolver
[`hickory-recursor`]: ../recursor

## Cryptography provider

Features requiring cryptography require selecting a specific cryptography
provider. See the [project README] for more information.

[project README]: ../../README.md#Cryptography-provider

## Protocol support

The following DNS protocols are optionally supported:

* DNS over TLS (DoT)
* DNS over HTTP/2 (DoH)
* DNS over QUIC (DoQ)
* DNS over HTTP/3 (DoH3)

In order to use these optional protocols you must enable a cargo feature
corresponding to your desired cryptography provider:

* DoT: `tls-aws-lc-rs` or `tls-ring`.
* DoH: `https-aws-lc-rs` or `https-ring`
* DoQ: `quic-aws-lc-rs` or `quic-ring`
* DoH3: `h3-aws-lc-rs` or `h3-ring`

## DNSSEC

In order to use DNSSEC you must enable a cargo feature corresponding to your desired 
cryptography provider:

* `dnssec-aws-lc-rs`
* `dnssec-ring`

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

## Other crate features

* `serde` - enable serde serialization support.
* `backtrace` - enable error backtrace collection.
* `mdns` (experimental) - enable experimental mDNS support.
* `rustls-platform-verifier` - use the system verifier for TLS with
  [rustls-platform-verifier].
* `webpki-roots` - use the [webpki-roots] crate for TLS certificate verification.

[rustls-platform-verifier]: https://crates.io/crates/rustls-platform-verifier
[webpki-roots]: https://crates.io/crates/webpki-roots

## Example

```rust
use std::net::SocketAddr;
use std::str::FromStr;

use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::rr::{DNSClass, Name, Record, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::xfer::DnsResponse;

let address = SocketAddr::from(([8, 8, 8, 8], 53));
let conn = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
let (mut client, bg) = Client::<TokioRuntimeProvider>::connect(conn).await.unwrap();
tokio::spawn(bg);

// Specify the name, note the final '.' which specifies it's an FQDN
let name = Name::from_str("www.example.com.").unwrap();

// NOTE: see 'Setup a connection' example above
// Send the query and get a message response, see RecordType for all supported options
let response: DnsResponse = client
    .query(name, DNSClass::IN, RecordType::A)
    .await
    .unwrap();

// Messages are the packets sent between client and server in DNS, DnsResponse's can be
//  dereferenced to a Message. There are many fields to a Message, It's beyond the scope
//  of these examples to explain them. See hickory_dns::op::message::Message for more details.
//  generally we will be interested in the Message::answers
let answers: &[Record] = response.answers();

// Records are generic objects which can contain any data.
//  In order to access it we need to first check what type of record it is
//  In this case we are interested in A, IPv4 address
let a_data = answers
    .iter()
    .flat_map(|record| record.data().as_a())
    .collect::<Vec<_>>();
assert!(!a_data.is_empty());
```

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
