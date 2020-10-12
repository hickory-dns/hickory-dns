#![recursion_limit = "128"]
#![cfg(feature = "trust-dns-resolver")]

extern crate trust_dns_client;
extern crate trust_dns_server;

use std::net::Ipv4Addr;
use std::str::FromStr;

use tokio::runtime::Runtime;

use trust_dns_client::rr::{Name, RecordType};
use trust_dns_server::authority::{Authority, LookupObject};
use trust_dns_server::store::forwarder::ForwardAuthority;

#[ignore]
#[test]
fn test_lookup() {
    let mut runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let forwarder = ForwardAuthority::new(runtime.handle().clone());
    let forwarder = runtime
        .block_on(forwarder)
        .expect("failed to create forwarder");

    let lookup = runtime
        .block_on(forwarder.lookup(
            &Name::from_str("www.example.com.").unwrap().into(),
            RecordType::A,
            false,
            Default::default(),
        ))
        .unwrap();

    let address = lookup.iter().next().expect("no addresses returned!");
    let address = address.rdata().as_a().expect("not an A record");
    assert_eq!(*address, Ipv4Addr::new(93, 184, 216, 34));
}
