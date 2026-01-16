#![cfg(all(feature = "__dnssec", feature = "sqlite"))]
#![allow(unreachable_pub)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

use futures_executor::block_on;

use hickory_net::{
    runtime::{Time, TokioTime},
    xfer::Protocol,
};
use hickory_proto::{
    dnssec::TSigner,
    dnssec::rdata::tsig::TsigAlgorithm,
    op::{Header, Message, MessageType, OpCode, Query, ResponseCode, update_message},
    rr::{
        DNSClass, Name, RData, Record, RecordSet, RecordType,
        rdata::{A as A4, AAAA},
    },
    serialize::binary::BinEncodable,
};
use hickory_server::{
    server::Request,
    store::sqlite::SqliteZoneHandler,
    zone_handler::{LookupError, LookupOptions, MessageRequest, ZoneHandler},
};

const TEST_HEADER: &Header = &Header::new(10, MessageType::Query, OpCode::Query);

fn update_zone_handler(
    mut message: Message,
    key: &TSigner,
    handler: &mut impl ZoneHandler,
) -> Result<bool, ResponseCode> {
    let now = TokioTime::current_time();
    message.finalize(key, now).expect("failed to sign message");
    let bytes = message.to_bytes().unwrap();
    let request = Request::from_bytes(
        bytes,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    block_on(handler.update(&request, now)).0
}

pub fn test_create(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("create.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(127, 0, 0, 10)));
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name, RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in zone handler")
            .data()
        {
            RData::A(ip) => assert_eq!(A4::new(127, 0, 0, 10), *ip),
            _ => panic!("wrong rdata type returned"),
        }

        // trying to create again should error
        let message =
            update_message::create(record.into(), Name::from_str("example.com.").unwrap(), true);
        assert_eq!(
            update_zone_handler(message, key, &mut handler).unwrap_err(),
            ResponseCode::YXRRSet
        );
    }
}

pub fn test_create_multi(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("create-multi.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();
        // create a record
        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        let mut record2 = record.clone();
        record2.set_data(RData::A(A4::new(100, 10, 100, 11)));
        let record2 = record2;

        let mut rrset = RecordSet::from(record.clone());
        rrset.insert(record2.clone(), 0);
        let rrset = rrset;

        let message =
            update_message::create(rrset.clone(), Name::from_str("example.com.").unwrap(), true);
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));

        // trying to create again should error
        let message = update_message::create(rrset, Name::from_str("example.com.").unwrap(), true);
        assert_eq!(
            update_zone_handler(message, key, &mut handler).unwrap_err(),
            ResponseCode::YXRRSet
        );
    }
}

pub fn test_append(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("append.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // append a record
        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        // first check the must_exist option
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert_eq!(
            update_zone_handler(message, key, &mut handler).unwrap_err(),
            ResponseCode::NXRRSet
        );

        // next append to a non-existent RRset
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            false,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        // verify record contents
        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == record));

        // will fail if already set and not the same value.
        let mut record2 = record.clone();
        record2.set_data(RData::A(A4::new(101, 11, 101, 11)));

        let message = update_message::append(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("append failed"));

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 2);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));

        // show that appending the same thing again is ok, but doesn't add any records
        let message = update_message::append(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("append failed"));

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 2);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));
    }
}

pub fn test_append_multi(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("append-multi.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // append a record
        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        // next append to a non-existent RRset
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            false,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("append failed"));

        // will fail if already set and not the same value.
        let mut record2 = record.clone();
        record2.set_data(RData::A(A4::new(101, 11, 101, 11)));
        let mut record3 = record.clone();
        record3.set_data(RData::A(A4::new(101, 11, 101, 12)));

        // build the append set
        let mut rrset = RecordSet::from(record2.clone());
        rrset.insert(record3.clone(), 0);

        let message = update_message::append(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("append failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 3);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));
        assert!(lookup.iter().any(|rr| *rr == record3));

        // show that appending the same thing again is ok, but doesn't add any records
        // TODO: technically this is a test for the Server, not client...
        let message = update_message::append(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("append failed"));

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 3);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));
        assert!(lookup.iter().any(|rr| *rr == record3));
    }
}

pub fn test_compare_and_swap(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("compare-and-swap.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // create a record
        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        let current = record;
        let mut new = current.clone();
        new.set_data(RData::A(A4::new(101, 11, 101, 11)));
        let new = new;

        let message = update_message::compare_and_swap(
            current.clone().into(),
            new.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("compare_and_swap failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == new));
        assert!(!lookup.iter().any(|rr| *rr == current));

        // check the it fails if tried again.
        let mut not = new.clone();
        not.set_data(RData::A(A4::new(102, 12, 102, 12)));
        let not = not;

        let message = update_message::compare_and_swap(
            current.into(),
            not.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert_eq!(
            update_zone_handler(message, key, &mut handler).unwrap_err(),
            ResponseCode::NXRRSet
        );

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == new));
        assert!(!lookup.iter().any(|rr| *rr == not));
    }
}

pub fn test_compare_and_swap_multi(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("compare-and-swap-multi.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // create a record
        let mut current = RecordSet::with_ttl(name.clone(), RecordType::A, 8);

        let current1 = current
            .new_record(&RData::A(A4::new(100, 10, 100, 10)))
            .clone();
        let current2 = current
            .new_record(&RData::A(A4::new(100, 10, 100, 11)))
            .clone();
        let current = current;

        let message = update_message::create(
            current.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        let mut new =
            RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
        let new1 = new.new_record(&RData::A(A4::new(100, 10, 101, 10))).clone();
        let new2 = new.new_record(&RData::A(A4::new(100, 10, 101, 11))).clone();
        let new = new;

        let message = update_message::compare_and_swap(
            current.clone(),
            new.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("compare_and_swap failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 2);
        assert!(lookup.iter().any(|rr| *rr == new1));
        assert!(lookup.iter().any(|rr| *rr == new2));
        assert!(!lookup.iter().any(|rr| *rr == current1));
        assert!(!lookup.iter().any(|rr| *rr == current2));

        // check the it fails if tried again.
        let mut not = new1.clone();
        not.set_data(RData::A(A4::new(102, 12, 102, 12)));
        let not = not;

        let message = update_message::compare_and_swap(
            current.clone(),
            not.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert_eq!(
            update_zone_handler(message, key, &mut handler).unwrap_err(),
            ResponseCode::NXRRSet
        );

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 2);
        assert!(lookup.iter().any(|rr| *rr == new1));
        assert!(!lookup.iter().any(|rr| *rr == not));
    }
}

pub fn test_delete_by_rdata(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("test-delete-by-rdata.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // append a record
        let record1 = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        // first check the must_exist option
        let message = update_message::delete_by_rdata(
            record1.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("delete_by_rdata failed"));

        // next create to a non-existent RRset
        let message = update_message::create(
            record1.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("delete_by_rdata failed"));

        let mut record2 = record1.clone();
        record2.set_data(RData::A(A4::new(101, 11, 101, 11)));
        let message = update_message::append(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("append failed"));

        // verify record contents
        let message = update_message::delete_by_rdata(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("delete_by_rdata failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == record1));
    }
}

pub fn test_delete_by_rdata_multi(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("test-delete-by-rdata-multi.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // append a record
        let mut rrset = RecordSet::with_ttl(name.clone(), RecordType::A, 8);

        let record1 = rrset
            .new_record(&RData::A(A4::new(100, 10, 100, 10)))
            .clone();
        let record2 = rrset
            .new_record(&RData::A(A4::new(100, 10, 100, 11)))
            .clone();
        let record3 = rrset
            .new_record(&RData::A(A4::new(100, 10, 100, 12)))
            .clone();
        let record4 = rrset
            .new_record(&RData::A(A4::new(100, 10, 100, 13)))
            .clone();
        let rrset = rrset;

        // first check the must_exist option
        let message = update_message::delete_by_rdata(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("delete_by_rdata failed"));

        // next create to a non-existent RRset
        let message =
            update_message::create(rrset.clone(), Name::from_str("example.com.").unwrap(), true);
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        // append a record
        let mut rrset = RecordSet::with_ttl(name.clone(), RecordType::A, 8);

        let record1 = rrset.new_record(record1.data()).clone();
        let record3 = rrset.new_record(record3.data()).clone();
        let rrset = rrset;

        let message = update_message::append(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("append failed"));

        // verify record contents
        let message = update_message::delete_by_rdata(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("delete_by_rdata failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()))
            .0
            .unwrap();

        assert_eq!(lookup.iter().count(), 2);
        assert!(!lookup.iter().any(|rr| *rr == record1));
        assert!(lookup.iter().any(|rr| *rr == record2));
        assert!(!lookup.iter().any(|rr| *rr == record3));
        assert!(lookup.iter().any(|rr| *rr == record4));
    }
}

pub fn test_delete_rrset(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("compare-and-swap-multi.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // append a record
        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        // first check the must_exist option
        let message = update_message::delete_rrset(
            record.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("delete_rrset failed"));

        // next create to a non-existent RRset
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        let mut record = record.clone();
        record.set_data(RData::A(A4::new(101, 11, 101, 11)));
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("append failed"));

        // verify record contents
        let message = update_message::delete_rrset(
            record.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("delete_rrset failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()));

        assert!(matches!(
            lookup.0.unwrap_err(),
            LookupError::ResponseCode(ResponseCode::NXDomain)
        ));
    }
}

pub fn test_delete_all(mut handler: impl ZoneHandler, keys: &[TSigner]) {
    let name = Name::from_str("compare-and-swap-multi.example.com.").unwrap();
    for key in keys {
        let name = key.algorithm().to_name().append_name(&name).unwrap();

        // append a record
        let record = Record::from_rdata(name.clone(), 8, RData::A(A4::new(100, 10, 100, 10)));

        // first check the must_exist option
        let message = update_message::delete_all(
            record.name().clone(),
            Name::from_str("example.com.").unwrap(),
            DNSClass::IN,
            true,
        );
        assert!(!update_zone_handler(message, key, &mut handler).expect("delete_all failed"));

        // next create to a non-existent RRset
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        let mut record = record.clone();
        record.set_data(RData::AAAA(AAAA::new(1, 2, 3, 4, 5, 6, 7, 8)));
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("create failed"));

        // verify record contents
        let message = update_message::delete_all(
            record.name().clone(),
            Name::from_str("example.com.").unwrap(),
            DNSClass::IN,
            true,
        );
        assert!(update_zone_handler(message, key, &mut handler).expect("delete_all failed"));

        let request = Request::from_message(
            MessageRequest::mock(*TEST_HEADER, Query::query(name.clone(), RecordType::A)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Protocol::Udp,
        )
        .unwrap();

        let lookup = block_on(handler.search(&request, LookupOptions::default()));
        assert!(matches!(
            lookup.0.unwrap_err(),
            LookupError::ResponseCode(ResponseCode::NXDomain)
        ));

        let lookup = block_on(handler.search(&request, LookupOptions::default()));
        assert!(matches!(
            lookup.0.unwrap_err(),
            LookupError::ResponseCode(ResponseCode::NXDomain)
        ));
    }
}

pub fn add_auth(handler: &mut SqliteZoneHandler) -> Vec<TSigner> {
    let mut keys = Vec::<TSigner>::new();

    #[cfg(feature = "__dnssec")]
    {
        let tsig_algorithms = [
            TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512,
        ];

        for algo in tsig_algorithms {
            let secret_key = b"test_secret_key_for_dynamic_update".to_vec();

            let key_name = Name::from_str(&format!("update-{}", algo.to_name().to_lowercase()))
                .unwrap()
                .append_domain(&handler.origin().to_owned().into())
                .unwrap();

            let signer =
                TSigner::new(secret_key, algo, key_name, 300).expect("failed to create TSigner");

            keys.push(signer);
        }

        handler.set_tsig_signers(keys.clone());
    }

    keys
}

macro_rules! define_update_test {
    ($new:expr; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                ::test_support::subscribe();
                use std::path::Path;
                let mut handler = $new(&Path::new("../tests/test-data/test_configs/example.com.zone"), module_path!(), stringify!($f));
                let keys = crate::zone_handler_battery::dynamic_update::add_auth(&mut handler);
                crate::zone_handler_battery::dynamic_update::$f(handler, &keys);
            }
        )*
    }
}

macro_rules! dynamic_update {
    ($name:ident, $new:expr) => {
        #[cfg(test)]
        mod dynamic_update {
            mod $name {
                define_update_test!($new;
                    test_create,
                    test_create_multi,
                    test_append,
                    test_append_multi,
                    test_compare_and_swap,
                    test_compare_and_swap_multi,
                    test_delete_by_rdata,
                    test_delete_by_rdata_multi,
                    test_delete_rrset,
                    test_delete_all,
                );
            }
        }
    };
}
