use std::str::FromStr;

use test_support::subscribe;
use tokio::runtime::Runtime;

use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::CNAME};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::{
    authority::{Authority, AxfrPolicy, ZoneType},
    store::in_memory::InMemoryAuthority,
};

#[test]
fn test_cname_loop() {
    subscribe();

    let runtime = Runtime::new().expect("failed to create Tokio Runtime");
    let mut auth = InMemoryAuthority::empty(
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

    let mut lookup = runtime
        .block_on(auth.lookup(
            &Name::from_str("foo.example.com.").unwrap().into(),
            RecordType::A,
            Default::default(),
        ))
        .unwrap();

    let records: Vec<&Record> = lookup.iter().collect();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name(), &Name::from_str("foo.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    assert!(
        lookup.take_additionals().is_none(),
        "Should be no additional records."
    );

    let mut lookup = runtime
        .block_on(auth.lookup(
            &Name::from_str("bar.example.com.").unwrap().into(),
            RecordType::A,
            Default::default(),
        ))
        .unwrap();

    let records: Vec<&Record> = lookup.iter().collect();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name(), &Name::from_str("bar.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    let additionals = lookup
        .take_additionals()
        .expect("Should be additional records");
    let additionals: Vec<&Record> = additionals.iter().collect();
    assert_eq!(additionals.len(), 1);
    let record = additionals[0];
    assert_eq!(record.name(), &Name::from_str("foo.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("foo.example.com.").unwrap()))
    );

    let mut lookup = runtime
        .block_on(auth.lookup(
            &Name::from_str("baz.example.com.").unwrap().into(),
            RecordType::A,
            Default::default(),
        ))
        .unwrap();

    let records: Vec<&Record> = lookup.iter().collect();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.name(), &Name::from_str("baz.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("boz.example.com.").unwrap()))
    );

    let additionals = lookup
        .take_additionals()
        .expect("Should be additional records");
    let additionals: Vec<&Record> = additionals.iter().collect();
    assert_eq!(additionals.len(), 2);
    let record = additionals[0];
    assert_eq!(record.name(), &Name::from_str("boz.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("biz.example.com.").unwrap()))
    );
    let record = additionals[1];
    assert_eq!(record.name(), &Name::from_str("biz.example.com.").unwrap());
    assert_eq!(
        record.data(),
        &RData::CNAME(CNAME(Name::from_str("baz.example.com.").unwrap()))
    );
}
