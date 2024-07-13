# Overview

Hickory DNS is a library which implements the DNS protocol and client side functions.

This library contains basic implementations for DNS record serialization, and communication. It is capable of performing `query`, `update`, and `notify` operations. `update` has been proven to be compatible with `BIND9` and `SIG0` signed records for updates. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The Hickory DNS [project](https://github.com/hickory-dns/hickory-dns) contains other libraries for DNS: a [resolver library](https://crates.io/crates/hickory-resolver) for lookups, a [server library](https://crates.io/crates/hickory-dns) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/hickory-dns-rustls) and [native-tls](https://crates.io/crates/hickory-dns-native-tls).

**NOTICE** This project was rebranded from Trust-DNS to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, this crate/binary has been moved to [hickory-client](https://crates.io/crates/hickory-client), from `0.24` and onward, for prior versions see [trust-dns-client](https://crates.io/crates/trust-dns-client).

## Featuress

The `client` is capable of DNSSEC validation as well as offering higher order functions for performing DNS operations:

- [SyncDnssecClient](https://docs.rs/hickory-client/latest/hickory_client/client/struct.SyncDnssecClient.html) - DNSSEC validation
- [create](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.create) - atomic create of a record, with authenticated request
- [append](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.append) - verify existence of a record and append to it
- [compare_and_swap](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.compare_and_swap) - atomic (depends on server) compare and swap
- [delete_by_rdata](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_by_rdata) - delete a specific record
- [delete_rrset](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_rrset) - delete an entire record set
- [delete_all](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.delete_all) - delete all records sets with a given name
- [notify](https://docs.rs/hickory-client/latest/hickory_client/client/trait.Client.html#method.notify) - notify server that it should reload a zone

## Example

```rust
use std::net::Ipv4Addr;
use std::str::FromStr;
use hickory_client::client::{Client, SyncClient};
use hickory_client::udp::UdpClientConnection;
use hickory_client::op::DnsResponse;
use hickory_client::rr::{rdata::A, DNSClass, Name, RData, Record, RecordType};

let address = "8.8.8.8:53".parse().unwrap();
let conn = UdpClientConnection::new(address).unwrap();
let client = SyncClient::new(conn);

// Specify the name, note the final '.' which specifies it's an FQDN
let name = Name::from_str("www.example.com.").unwrap();

// NOTE: see 'Setup a connection' example above
// Send the query and get a message response, see RecordType for all supported options
let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

// Messages are the packets sent between client and server in DNS, DnsResonse's can be
//  dereferenced to a Message. There are many fields to a Message, It's beyond the scope
//  of these examples to explain them. See hickory_dns::op::message::Message for more details.
//  generally we will be interested in the Message::answers
let answers: &[Record] = response.answers();

// Records are generic objects which can contain any data.
//  In order to access it we need to first check what type of record it is
//  In this case we are interested in A, IPv4 address
if let Some(RData::A(A(ref ip))) = answers[0].data() {
    assert_eq!(*ip, Ipv4Addr::new(93, 184, 215, 14))
} else {
    assert!(false, "unexpected result")
}
```

## DNS-over-TLS and DNS-over-HTTPS

DoT and DoH are supported. This is accomplished through the use of one of `native-tls`, `openssl`, or `rustls` (only `rustls` is currently supported for DoH).

To use with the `Client`, the `TlsClientConnection` or `HttpsClientConnection` should be used. Similarly, to use with the tokio `AsyncClient` the `TlsClientStream` or `HttpsClientStream` should be used. ClientAuth, mTLS, is currently not supported, there are some issues still being worked on. TLS is useful for Server authentication and connection privacy.

To enable DoT one of the features `dns-over-native-tls`, `dns-over-openssl`, or `dns-over-rustls` must be enabled, `dns-over-https-rustls` is used for DoH.

## DNSSEC status

Currently the root key is hardcoded into the system. This gives validation of
DNSKEY and DS records back to the root. NSEC is implemented, but not NSEC3.
Because caching is not yet enabled, it has been noticed that some DNS servers
appear to rate limit the connections, validating RRSIG records back to the root
can require a significant number of additional queries for those records.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, one of the features `dnssec-openssl` or `dnssec-ring` must be enabled.

## Minimum Rust Version

The current minimum rustc version for this project is `1.67`

## Versioning

Hickory DNS does it's best job to follow semver. Hickory DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Hickory DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Hickory DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.
