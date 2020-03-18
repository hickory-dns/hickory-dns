# Overview

Trust-DNS is a library which implements the DNS protocol and client side functions.

This library contains basic implementations for DNS record serialization, and communication. It is capable of performing `query`, `update`, and `notify` operations. `update` has been proven to be compatible with `BIND9` and `SIG0` signed records for updates. It is built on top of the [tokio](https://tokio.rs) async-io project, this allows it to be integrated into other systems using the tokio and futures libraries. The Trust-DNS [project](https://github.com/bluejekyll/trust-dns) contains other libraries for DNS: a [resolver library](https://crates.io/crates/trust-dns-resolver) for lookups, a [server library](https://crates.io/crates/trust-dns) for hosting zones, and variations on the TLS implementation over [rustls](https://crates.io/crates/trust-dns-rustls) and [native-tls](https://crates.io/crates/trust-dns-native-tls).

## Features

The `client` is capable of DNSSec validation as well as offering higher order functions for performing DNS operations:

- [SyncDnssecClient](https://docs.rs/trust-dns/0.11.0/trust_dns/client/struct.SyncDnssecClient.html) - DNSSec validation
- [create](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.create) - atomic create of a record, with authenticated request
- [append](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.append) - verify existence of a record and append to it
- [compare_and_swap](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.compare_and_swap) - atomic (depends on server) compare and swap
- [delete_by_rdata](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.delete_by_rdata) - delete a specific record
- [delete_rrset](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.delete_rrset) - delete an entire record set
- [delete_all](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.delete_all) - delete all records sets with a given name
- [notify](https://docs.rs/trust-dns/0.11.0/trust_dns/client/trait.Client.html#method.notify) - notify server that it should reload a zone

## Example

```rust
use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns::client::{Client, SyncClient};
use trust_dns::udp::UdpClientConnection;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};

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
//  of these examples to explain them. See trust_dns::op::message::Message for more details.
//  generally we will be interested in the Message::answers
let answers: &[Record] = response.answers();

// Records are generic objects which can contain any data.
//  In order to access it we need to first check what type of record it is
//  In this case we are interested in A, IPv4 address
if let &RData::A(ref ip) = answers[0].rdata() {
    assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34))
} else {
    assert!(false, "unexpected result")
}
```

## DNS-over-TLS and DNS-over-HTTPS

DoT and DoH are supported. This is accomplished through the use of one of `native-tls`, `openssl`, or `rustls` (only `rustls` is currently supported for DoH).

To use with the `Client`, the `TlsClientConnection` or `HttpsClientConnection` should be used. Similarly, to use with the tokio `AsyncClient` the `TlsClientStream` or `HttpsClientStream` should be used. ClientAuth, mTLS, is currently not supported, there are some issues still being worked on. TLS is useful for Server authentication and connection privacy.

To enable DoT one of the features `dns-over-native-tls`, `dns-over-openssl`, or `dns-over-rustls` must be enabled, `dns-over-https-rustls` is used for DoH.

## DNSSec status

Currently the root key is hardcoded into the system. This gives validation of
 DNSKEY and DS records back to the root. NSEC is implemented, but not NSEC3.
 Because caching is not yet enabled, it has been noticed that some DNS servers
 appear to rate limit the connections, validating RRSIG records back to the root
 can require a significant number of additional queries for those records.

Zones will be automatically resigned on any record updates via dynamic DNS. To enable DNSSEC, one of the features `dnssec-openssl` or `dnssec-rustls` must be enabled.

## Minimum Rust Version

The current minimum rustc version for this project is `1.40`

## Versioning

Trust-DNS does it's best job to follow semver. Trust-DNS will be promoted to 1.0 upon stabilization of the publicly exposed APIs. This does not mean that Trust-DNS will necessarily break on upgrades between 0.x updates. Whenever possible, old APIs will be deprecated with notes on what replaced those deprecations. Trust-DNS will make a best effort to never break software which depends on it due to API changes, though this can not be guaranteed. Deprecated interfaces will be maintained for at minimum one major release after that in which they were deprecated (where possible), with the exception of the upgrade to 1.0 where all deprecated interfaces will be planned to be removed.