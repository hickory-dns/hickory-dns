use std::str::FromStr;

use test_support::subscribe;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::CNAME};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::{
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, LookupOptions, ZoneHandler, ZoneType},
};

#[tokio::test]
async fn test_cname_loop() {
    subscribe();
    let mut auth = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
        Name::from_str("example.com.").unwrap(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("foo.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("bar.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("baz.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("boz.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("boz.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("biz.example.com.").unwrap())),
        ),
        0,
    );

    auth.upsert_mut(
        Record::from_rdata(
            Name::from_str("biz.example.com.").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str("baz.example.com.").unwrap())),
        ),
        0,
    );

    let lookup = auth
        .lookup(
            &Name::from_str("foo.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    let records = lookup.iter().collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name, Name::from_str("foo.example.com.").unwrap());
    assert_eq!(
        record.data,
        RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    assert!(
        lookup.additionals().is_none(),
        "Should be no additional records."
    );

    let lookup = auth
        .lookup(
            &Name::from_str("bar.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    let records = lookup.iter().collect::<Vec<_>>();
    // bar -> foo (self-referencing): both CNAMEs in the answer section
    assert_eq!(records.len(), 2);
    let record = records[0];
    assert_eq!(record.name, Name::from_str("bar.example.com.").unwrap());
    assert_eq!(
        record.data,
        RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );
    let record = records[1];
    assert_eq!(record.name, Name::from_str("foo.example.com.").unwrap());
    assert_eq!(
        record.data,
        RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    assert!(
        lookup.additionals().is_none(),
        "Should be no additional records."
    );

    let lookup = auth
        .lookup(
            &Name::from_str("baz.example.com.").unwrap().into(),
            RecordType::A,
            None,
            LookupOptions::default(),
        )
        .await
        .unwrap();

    let records = lookup.iter().collect::<Vec<_>>();
    // baz -> boz -> biz -> baz (loop): full chain in the answer section
    assert_eq!(records.len(), 3);
    let record = records[0];
    assert_eq!(record.name, Name::from_str("baz.example.com.").unwrap());
    assert_eq!(
        record.data,
        RData::CNAME(CNAME(Name::from_str("boz.example.com.").unwrap()))
    );
    let record = records[1];
    assert_eq!(record.name, Name::from_str("boz.example.com.").unwrap());
    assert_eq!(
        record.data,
        RData::CNAME(CNAME(Name::from_str("biz.example.com.").unwrap()))
    );
    let record = records[2];
    assert_eq!(record.name, Name::from_str("biz.example.com.").unwrap());
    assert_eq!(
        record.data,
        RData::CNAME(CNAME(Name::from_str("baz.example.com.").unwrap()))
    );

    assert!(
        lookup.additionals().is_none(),
        "Should be no additional records."
    );
}
