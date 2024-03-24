#![recursion_limit = "128"]
#![cfg(feature = "hickory-resolver")]

use std::net::Ipv4Addr;
use std::str::FromStr;

use tokio::runtime::Runtime;

use hickory_proto::rr::{Name, RData, RecordType};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_server::{
    authority::{Authority, LookupObject},
    store::forwarder::ForwardAuthority,
};

#[ignore]
#[test]
fn test_lookup() {
    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let forwarder = ForwardAuthority::new(TokioConnectionProvider::default())
        .expect("failed to create forwarder");

    let lookup = runtime
        .block_on(forwarder.lookup(
            &Name::from_str("www.example.com.").unwrap().into(),
            RecordType::A,
            Default::default(),
        ))
        .unwrap()
        .unwrap();

    let address = lookup.iter().next().expect("no addresses returned!");
    let address = address
        .data()
        .and_then(RData::as_a)
        .expect("not an A record");
    assert_eq!(*address, Ipv4Addr::new(93, 184, 216, 34).into());
}
