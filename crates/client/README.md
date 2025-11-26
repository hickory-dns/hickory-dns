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

## Status

The Hickory DNS Client is intended to be used for operating against a DNS server
directly. It can be used for verifying records or updating records for servers
that support SIG0 and dynamic update. The Client is also capable of validating
DNSSEC. NSEC and NSEC3 validation are supported. Today, the Tokio async runtime
is required.

## Features

The `client` is capable of DNSSEC validation as well as offering higher order functions for performing DNS operations:

- [SyncDnssecClient](https://docs.rs/hickory-client/latest/hickory_client/client/struct.SyncDnssecClient.html) - DNSSEC validation
- [create](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.create) - atomic create of a record, with authenticated request
- [append](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.append) - verify existence of a record and append to it
- [compare_and_swap](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.compare_and_swap) - atomic (depends on server) compare and swap
- [delete_by_rdata](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_by_rdata) - delete a specific record
- [delete_rrset](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_rrset) - delete an entire record set
- [delete_all](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_all) - delete all records sets with a given name
- [notify](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.notify) - notify server that it should reload a zone

## Optional protocol support

The following DNS protocols are optionally supported:

- Enable `dns-over-rustls` for DNS over TLS (DoT)
- Enable `dns-over-https-rustls` for DNS over HTTP/2 (DoH)
- Enable `dns-over-quic` for DNS over QUIC (DoQ)
- Enable `dns-over-h3` for DNS over HTTP/3 (DoH3)

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

## DNSSEC status

The current root key is bundled into the system, and used by default. This gives
validation of DNSKEY and DS records back to the root. NSEC and NSEC3 are
implemented.

To enable DNSSEC, enable the `dnssec-ring` feature.

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
