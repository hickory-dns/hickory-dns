#![cfg(feature = "resolver")]

use std::str::FromStr;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_server::{
    store::forwarder::ForwardZoneHandler,
    zone_handler::{LookupOptions, ZoneHandler},
};
use test_support::subscribe;

#[tokio::test]
async fn test_lookup() {
    subscribe();

    let forwarder = ForwardZoneHandler::builder(TokioRuntimeProvider::default())
        .unwrap()
        .build()
        .expect("failed to create forwarder");

    let lookup = forwarder
        .lookup(
            &Name::from_str("www.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    assert!(
        lookup
            .iter()
            .any(|record| matches!(record.data(), RData::A(_))),
        "no addresses returned!"
    );
}
