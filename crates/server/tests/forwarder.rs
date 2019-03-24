#![recursion_limit = "128"]

extern crate trust_dns;
extern crate trust_dns_server;

use std::net::Ipv4Addr;
use std::str::FromStr;

use trust_dns::rr::{Name, RecordType};
use trust_dns_server::authority::{Authority, LookupObject};
use trust_dns_server::store::forwarder::ForwardAuthority;

#[test]
fn test_lookup() {
    let forwarder = ForwardAuthority::new();

    let lookup = forwarder.lookup(
        &Name::from_str("www.example.com.").unwrap().into(),
        RecordType::A,
        false,
        Default::default(),
    ).unwrap();

    let address = lookup.iter().next().expect("no addresses returned!");
    let address = address.rdata().as_a().expect("not an A record");
    assert_eq!(*address, Ipv4Addr::new(93, 184, 216, 34));
}
