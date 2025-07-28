#![cfg(feature = "resolver")]

use std::str::FromStr;

use tokio::runtime::Runtime;

use hickory_proto::{
    rr::{Name, RecordType},
    runtime::TokioRuntimeProvider,
};
use hickory_server::{authority::Authority, store::forwarder::ForwardAuthority};
use test_support::subscribe;

#[test]
fn test_lookup() {
    subscribe();

    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let forwarder = ForwardAuthority::builder(TokioRuntimeProvider::default())
        .unwrap()
        .build()
        .expect("failed to create forwarder");

    let lookup = runtime
        .block_on(forwarder.lookup(
            &Name::from_str("www.example.com.").unwrap().into(),
            RecordType::A,
            None,
            Default::default(),
        ))
        .unwrap();

    assert!(
        lookup.iter().any(|record| record.data().as_a().is_some()),
        "no addresses returned!"
    );
}
