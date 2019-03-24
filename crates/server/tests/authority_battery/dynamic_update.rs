#![cfg(feature = "dnssec")]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use trust_dns::op::update_message;
use trust_dns::op::{Message, Query, ResponseCode};
use trust_dns::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use trust_dns::rr::dnssec::{Algorithm, Signer, SupportedAlgorithms, Verifier};
use trust_dns::serialize::binary::{BinDecodable, BinEncodable};
use trust_dns_server::authority::{Authority, MessageRequest, UpdateResult};

fn update_authority<A: Authority<Lookup = AuthLookup>>(
    mut message: Message,
    key: &Signer,
    authority: &mut A,
) -> UpdateResult<bool> {
    message.finalize(key, 1).expect("failed to sign message");
    let message = message.to_bytes().unwrap();
    let request = MessageRequest::from_bytes(&message).unwrap();

    authority.update(&request)
}

pub fn test_create<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("create.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);
        let record = Record::from_rdata(
            name.clone(),
            8,
            RecordType::A,
            RData::A(Ipv4Addr::new(127, 0, 0, 10)),
        );
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        let query = Query::query(name, RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in authity")
            .rdata()
        {
            RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 10), *ip),
            _ => panic!("wrong rdata type returned"),
        }

        // trying to create again should error
        let mut message =
            update_message::create(record.into(), Name::from_str("example.com.").unwrap());
        assert_eq!(
            update_authority(message, key, &mut authority).unwrap_err(),
            ResponseCode::YXRRSet
        );
    }
}

pub fn test_create_multi<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("create-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);
        // create a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
        let record = record;

        let mut record2 = record.clone();
        record2.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 11)));
        let record2 = record2;

        let mut rrset = RecordSet::from(record.clone());
        rrset.insert(record2.clone(), 0);
        let rrset = rrset;

        let message = update_message::create(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        let query = Query::query(name, RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));

        // trying to create again should error
        let message = update_message::create(rrset, Name::from_str("example.com.").unwrap());
        assert_eq!(
            update_authority(message, key, &mut authority).unwrap_err(),
            ResponseCode::YXRRSet
        );
    }
}

pub fn test_append<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("append.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // append a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

        // first check the must_exist option
        let mut message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert_eq!(
            update_authority(message, key, &mut authority).unwrap_err(),
            ResponseCode::NXRRSet
        );

        // next append to a non-existent RRset
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            false,
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        // verify record contents
        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == record));

        // will fail if already set and not the same value.
        let mut record2 = record.clone();
        record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));

        let message = update_message::append(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_authority(message, key, &mut authority).expect("append failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 2);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));

        // show that appending the same thing again is ok, but doesn't add any records
        let message = update_message::append(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(!update_authority(message, key, &mut authority).expect("append failed"));

        let query = Query::query(name, RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 2);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));
    }
}

pub fn test_append_multi<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("append-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // append a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

        // next append to a non-existent RRset
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            false,
        );
        assert!(update_authority(message, key, &mut authority).expect("append failed"));

        // will fail if already set and not the same value.
        let mut record2 = record.clone();
        record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
        let mut record3 = record.clone();
        record3.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 12)));

        // build the append set
        let mut rrset = RecordSet::from(record2.clone());
        rrset.insert(record3.clone(), 0);

        let message = update_message::append(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_authority(message, key, &mut authority).expect("append failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

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
        );
        assert!(!update_authority(message, key, &mut authority).expect("append failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 3);

        assert!(lookup.iter().any(|rr| *rr == record));
        assert!(lookup.iter().any(|rr| *rr == record2));
        assert!(lookup.iter().any(|rr| *rr == record3));
    }
}

pub fn test_compare_and_swap<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("compare-and-swap.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // create a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));
        let record = record;

        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        let current = record;
        let mut new = current.clone();
        new.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
        let new = new;

        let message = update_message::compare_and_swap(
            current.clone().into(),
            new.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("compare_and_swap failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == new));
        assert!(!lookup.iter().any(|rr| *rr == current));

        // check the it fails if tried again.
        let mut not = new.clone();
        not.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));
        let not = not;

        let message = update_message::compare_and_swap(
            current.into(),
            not.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert_eq!(
            update_authority(message, key, &mut authority).unwrap_err(),
            ResponseCode::NXRRSet
        );

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == new));
        assert!(!lookup.iter().any(|rr| *rr == not));
    }
}

pub fn test_compare_and_swap_multi<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("compare-and-swap-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // create a record
        let mut current = RecordSet::with_ttl(name.clone(), RecordType::A, 8);

        let current1 = current
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 10)))
            .clone();
        let current2 = current
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 11)))
            .clone();
        let current = current;

        let mut message = update_message::create(
            current.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        let mut new =
            RecordSet::with_ttl(current.name().clone(), current.record_type(), current.ttl());
        let new1 = new
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 10)))
            .clone();
        let new2 = new
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 101, 11)))
            .clone();
        let new = new;

        let mut message = update_message::compare_and_swap(
            current.clone(),
            new.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("compare_and_swap failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 2);
        assert!(lookup.iter().any(|rr| *rr == new1));
        assert!(lookup.iter().any(|rr| *rr == new2));
        assert!(!lookup.iter().any(|rr| *rr == current1));
        assert!(!lookup.iter().any(|rr| *rr == current2));

        // check the it fails if tried again.
        let mut not = new1.clone();
        not.set_rdata(RData::A(Ipv4Addr::new(102, 12, 102, 12)));
        let not = not;

        let message = update_message::compare_and_swap(
            current.clone(),
            not.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert_eq!(
            update_authority(message, key, &mut authority).unwrap_err(),
            ResponseCode::NXRRSet
        );

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 2);
        assert!(lookup.iter().any(|rr| *rr == new1));
        assert!(!lookup.iter().any(|rr| *rr == not));
    }
}

pub fn test_delete_by_rdata<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("test-delete-by-rdata.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // append a record
        let mut record1 = Record::with(name.clone(), RecordType::A, 8);
        record1.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

        // first check the must_exist option
        let mut message = update_message::delete_by_rdata(
            record1.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(!update_authority(message, key, &mut authority).expect("delete_by_rdata failed"));

        // next create to a non-existent RRset
        let mut message = update_message::create(
            record1.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("delete_by_rdata failed"));

        let mut record2 = record1.clone();
        record2.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
        let message = update_message::append(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_authority(message, key, &mut authority).expect("append failed"));

        // verify record contents
        let message = update_message::delete_by_rdata(
            record2.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("delete_by_rdata failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 1);
        assert!(lookup.iter().any(|rr| *rr == record1));
    }
}

pub fn test_delete_by_rdata_multi<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("test-delete-by-rdata-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);
        // append a record
        let mut rrset = RecordSet::with_ttl(name.clone(), RecordType::A, 8);

        let record1 = rrset
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 10)))
            .clone();
        let record2 = rrset
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 11)))
            .clone();
        let record3 = rrset
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 12)))
            .clone();
        let record4 = rrset
            .new_record(&RData::A(Ipv4Addr::new(100, 10, 100, 13)))
            .clone();
        let rrset = rrset;

        // first check the must_exist option
        let message = update_message::delete_by_rdata(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(!update_authority(message, key, &mut authority).expect("delete_by_rdata failed"));

        // next create to a non-existent RRset
        let message = update_message::create(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        // append a record
        let mut rrset = RecordSet::with_ttl(name.clone(), RecordType::A, 8);

        let record1 = rrset.new_record(record1.rdata()).clone();
        let record3 = rrset.new_record(record3.rdata()).clone();
        let rrset = rrset;

        let message = update_message::append(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(!update_authority(message, key, &mut authority).expect("append failed"));

        // verify record contents
        let message = update_message::delete_by_rdata(
            rrset.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("delete_by_rdata failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());

        assert_eq!(lookup.iter().count(), 2);
        assert!(!lookup.iter().any(|rr| *rr == record1));
        assert!(lookup.iter().any(|rr| *rr == record2));
        assert!(!lookup.iter().any(|rr| *rr == record3));
        assert!(lookup.iter().any(|rr| *rr == record4));
    }
}

pub fn test_delete_rrset<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("compare-and-swap-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // append a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

        // first check the must_exist option
        let message = update_message::delete_rrset(
            record.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(!update_authority(message, key, &mut authority).expect("delete_rrset failed"));

        // next create to a non-existent RRset
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        let mut record = record.clone();
        record.set_rdata(RData::A(Ipv4Addr::new(101, 11, 101, 11)));
        let message = update_message::append(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
            true,
        );
        assert!(update_authority(message, key, &mut authority).expect("append failed"));

        // verify record contents
        let message = update_message::delete_rrset(
            record.clone(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("delete_rrset failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());
        assert_eq!(lookup.iter().count(), 0);
    }
}

pub fn test_delete_all<A: Authority<Lookup = AuthLookup>>(mut authority: A, keys: &[Signer]) {
    let name = Name::from_str("compare-and-swap-multi.example.com.").unwrap();
    for key in keys {
        let name = Name::from_str(key.algorithm().as_str())
            .unwrap()
            .append_name(&name);

        // append a record
        let mut record = Record::with(name.clone(), RecordType::A, 8);
        record.set_rdata(RData::A(Ipv4Addr::new(100, 10, 100, 10)));

        // first check the must_exist option
        let message = update_message::delete_all(
            record.name().clone(),
            Name::from_str("example.com.").unwrap(),
            DNSClass::IN,
        );
        assert!(!update_authority(message, key, &mut authority).expect("delete_all failed"));

        // next create to a non-existent RRset
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        let mut record = record.clone();
        record.set_rr_type(RecordType::AAAA);
        record.set_rdata(RData::AAAA(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)));
        let message = update_message::create(
            record.clone().into(),
            Name::from_str("example.com.").unwrap(),
        );
        assert!(update_authority(message, key, &mut authority).expect("create failed"));

        // verify record contents
        let message = update_message::delete_all(
            record.name().clone(),
            Name::from_str("example.com.").unwrap(),
            DNSClass::IN,
        );
        assert!(update_authority(message, key, &mut authority).expect("delete_all failed"));

        let query = Query::query(name.clone(), RecordType::A);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());
        assert_eq!(lookup.iter().count(), 0);

        let query = Query::query(name.clone(), RecordType::AAAA);
        let lookup = authority.search(&query.into(), false, SupportedAlgorithms::new());
        assert_eq!(lookup.iter().count(), 0);
    }
}

pub fn add_auth<A: Authority<Lookup = AuthLookup>>(authority: &mut A) -> Vec<Signer> {
    use trust_dns::rr::rdata::key::KeyUsage;
    use trust_dns_server::config::dnssec::*;

    let update_name = Name::from_str("update")
        .unwrap()
        .append_domain(&authority.origin().to_owned().into());

    let mut keys = Vec::<Signer>::new();

    // TODO: support RSA signing with ring
    // rsa
    #[cfg(feature = "dnssec-openssl")]
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/rsa_2048.pem".to_string(),
            password: Some("123456".to_string()),
            algorithm: Algorithm::RSASHA512.to_string(),
            signer_name: Some(update_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config
            .try_into_signer(update_name.clone())
            .expect("failed to read key_config");
        let public_key = signer
            .key()
            .to_sig0key_with_usage(Algorithm::RSASHA512, KeyUsage::Host)
            .expect("failed to get sig0 key");

        authority
            .add_update_auth_key(update_name.clone(), public_key)
            .expect("failed to add signer to zone");
        keys.push(signer);
    }

    // // TODO: why are ecdsa tests failing in this context?
    // // ecdsa_p256
    // {
    //     let key_config = KeyConfig {
    //         key_path: "tests/named_test_configs/dnssec/ecdsa_p256.pem".to_string(),
    //         password: None,
    //         algorithm: Algorithm::ECDSAP256SHA256.to_string(),
    //         signer_name: Some(signer_name.clone().to_string()),
    //         is_zone_signing_key: Some(true),
    //         is_zone_update_auth: Some(false),
    //     };

    //     let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
    //     keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
    //     authority.add_zone_signing_key(signer).expect("failed to add signer to zone");
    //     authority.secure_zone().expect("failed to sign zone");
    // }

    // // ecdsa_p384
    // {
    //     let key_config = KeyConfig {
    //         key_path: "tests/named_test_configs/dnssec/ecdsa_p384.pem".to_string(),
    //         password: None,
    //         algorithm: Algorithm::ECDSAP384SHA384.to_string(),
    //         signer_name: Some(signer_name.clone().to_string()),
    //         is_zone_signing_key: Some(true),
    //         is_zone_update_auth: Some(false),
    //     };

    //     let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
    //     keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
    //     authority.add_zone_signing_key(signer).expect("failed to add signer to zone");
    //     authority.secure_zone().expect("failed to sign zone");
    // }

    // ed 25519
    #[cfg(feature = "dnssec-ring")]
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/ed25519.pk8".to_string(),
            password: None,
            algorithm: Algorithm::ED25519.to_string(),
            signer_name: Some(update_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config
            .try_into_signer(update_name.clone())
            .expect("failed to read key_config");
        let public_key = signer
            .key()
            .to_sig0key_with_usage(Algorithm::ED25519, KeyUsage::Host)
            .expect("failed to get sig0 key");

        authority
            .add_update_auth_key(update_name, public_key)
            .expect("failed to add signer to zone");
        keys.push(signer);
    }

    keys
}

macro_rules! define_update_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let mut authority = ::$new("tests/named_test_configs/example.com.zone", module_path!(), stringify!($f));
                let keys = ::authority_battery::dynamic_update::add_auth(&mut authority);
                ::authority_battery::dynamic_update::$f(authority, &keys);
            }
        )*
    }
}

macro_rules! dynamic_update {
    ($new:ident) => {
        #[cfg(test)]
        mod dynamic_update {
            mod $new {
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
