#![cfg(feature = "dnssec")]

use std::str::FromStr;
use std::{future::Future, sync::Arc};

use futures_executor::block_on;

use hickory_proto::{
    op::{Header, Query},
    rr::{
        dnssec::{
            rdata::{DNSKEY, RRSIG},
            Algorithm, SupportedAlgorithms, Verifier,
        },
        DNSClass, Name, RData, Record, RecordType,
    },
    xfer,
};
use hickory_server::{
    authority::{AuthLookup, Authority, DnssecAuthority, LookupOptions},
    server::{Protocol, RequestInfo},
};

const TEST_HEADER: &Header = &Header::new();

pub fn test_a_lookup<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A).into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(
        request_info,
        LookupOptions::for_dnssec(true, SupportedAlgorithms::new()),
    ))
    .unwrap();

    let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::A);

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(|r| Record::<RRSIG>::try_from(r).ok())
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&a_records, &rrsig_records, keys);
}

#[allow(clippy::unreadable_literal)]
pub fn test_soa<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    let lookup =
        block_on(authority.soa_secure(LookupOptions::for_dnssec(true, SupportedAlgorithms::new())))
            .unwrap();

    let (soa_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::SOA);

    assert_eq!(soa_records.len(), 1);

    let soa = soa_records.first().unwrap().data().as_soa().unwrap();

    assert_eq!(Name::from_str("hickory-dns.org.").unwrap(), *soa.mname());
    assert_eq!(
        Name::from_str("root.hickory-dns.org.").unwrap(),
        *soa.rname()
    );
    assert!(199609203 < soa.serial()); // serial should be one or more b/c of the signing process
    assert_eq!(28800, soa.refresh());
    assert_eq!(7200, soa.retry());
    assert_eq!(604800, soa.expire());
    assert_eq!(86400, soa.minimum());

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(|r| Record::<RRSIG>::try_from(r).ok())
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&soa_records, &rrsig_records, keys);
}

pub fn test_ns<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    let lookup =
        block_on(authority.ns(LookupOptions::for_dnssec(true, SupportedAlgorithms::new())))
            .unwrap();

    let (ns_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::NS);

    assert_eq!(
        ns_records.first().unwrap().data().as_ns().unwrap().0,
        Name::from_str("bbb.example.com.").unwrap()
    );

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(|r| Record::<RRSIG>::try_from(r).ok())
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&ns_records, &rrsig_records, keys);
}

pub fn test_aname_lookup<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    let query = Query::query(
        Name::from_str("aname-chain.example.com.").unwrap(),
        RecordType::A,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(
        request_info,
        LookupOptions::for_dnssec(true, SupportedAlgorithms::new()),
    ))
    .unwrap();

    let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::A);

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(|r| Record::<RRSIG>::try_from(r).ok())
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&a_records, &rrsig_records, keys);
}

pub fn test_wildcard<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    // check wildcard lookup
    let query = Query::query(
        Name::from_str("www.wildcard.example.com.").unwrap(),
        RecordType::CNAME,
    )
    .into();
    let request_info = RequestInfo::new(
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
        TEST_HEADER,
        &query,
    );

    let lookup = block_on(authority.search(
        request_info,
        LookupOptions::for_dnssec(true, SupportedAlgorithms::new()),
    ))
    .expect("lookup of www.wildcard.example.com. failed");

    let (cname_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::CNAME);

    assert!(cname_records
        .iter()
        .all(|r| *r.name() == Name::from_str("www.wildcard.example.com.").unwrap()));

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(|r| Record::<RRSIG>::try_from(r).ok())
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&cname_records, &rrsig_records, keys);
}

pub fn test_nsec_nodata<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    // this should have a single nsec record that covers the type
    let name = Name::from_str("www.example.com.").unwrap();
    let lookup = block_on(authority.get_nsec_records(
        &name.clone().into(),
        LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
    ))
    .unwrap();

    let (nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);

    println!("nsec_records: {nsec_records:?}");

    // there should only be one, and it should match the www.example.com name
    assert_eq!(nsec_records.len(), 1);
    assert_eq!(nsec_records.first().unwrap().name(), &name);

    let nsecs: Vec<&Record> = nsec_records.iter().collect();

    let query = Query::query(name, RecordType::TXT);
    assert!(xfer::dnssec_dns_handle::verify_nsec(
        &query,
        &Name::from_str("example.com.").unwrap(),
        &nsecs
    )
    .is_secure());
}

pub fn test_nsec_nxdomain_start<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    // tests between the SOA and first record in the zone, where bbb is the first zone record
    let name = Name::from_str("aaa.example.com.").unwrap();
    let lookup = block_on(authority.get_nsec_records(
        &name.clone().into(),
        LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
    ))
    .unwrap();

    let (nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);

    println!("nsec_records: {nsec_records:?}");

    // there should only be one, and it should match the www.example.com name
    assert!(!nsec_records.is_empty());
    // because the first record is from the SOA, the wildcard isn't necessary
    //  that is `example.com.` -> `bbb.example.com.` proves there is no wildcard.
    assert_eq!(nsec_records.len(), 1);

    let nsecs: Vec<&Record> = nsec_records.iter().collect();

    let query = Query::query(name, RecordType::A);
    assert!(xfer::dnssec_dns_handle::verify_nsec(
        &query,
        &Name::from_str("example.com.").unwrap(),
        &nsecs
    )
    .is_secure());
}

pub fn test_nsec_nxdomain_middle<A: Authority<Lookup = AuthLookup>>(authority: A, keys: &[DNSKEY]) {
    // follows the first record, nsec should cover between ccc and www, where bbb is the first zone record
    let name = Name::from_str("ccc.example.com.").unwrap();
    let lookup = block_on(authority.get_nsec_records(
        &name.clone().into(),
        LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
    ))
    .unwrap();

    let (nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);

    println!("nsec_records: {nsec_records:?}");

    // there should only be one, and it should match the www.example.com name
    assert!(!nsec_records.is_empty());
    // one record covers between the names, the other is for the wildcard proof.
    assert_eq!(nsec_records.len(), 2);

    let nsecs: Vec<&Record> = nsec_records.iter().collect();

    let query = Query::query(name, RecordType::A);
    assert!(xfer::dnssec_dns_handle::verify_nsec(
        &query,
        &Name::from_str("example.com.").unwrap(),
        &nsecs
    )
    .is_secure());
}

pub fn test_nsec_nxdomain_wraps_end<A: Authority<Lookup = AuthLookup>>(
    authority: A,
    keys: &[DNSKEY],
) {
    // wraps back to the beginning of the zone, where www is the last zone record
    let name = Name::from_str("zzz.example.com.").unwrap();
    let lookup = block_on(authority.get_nsec_records(
        &name.clone().into(),
        LookupOptions::for_dnssec(true, SupportedAlgorithms::all()),
    ))
    .unwrap();

    let (nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);

    println!("nsec_records: {nsec_records:?}");

    // there should only be one, and it should match the www.example.com name
    assert!(!nsec_records.is_empty());
    // one record covers between the names, the other is for the wildcard proof.
    assert_eq!(nsec_records.len(), 2);

    let nsecs: Vec<&Record> = nsec_records.iter().collect();

    let query = Query::query(name, RecordType::A);
    assert!(xfer::dnssec_dns_handle::verify_nsec(
        &query,
        &Name::from_str("example.com.").unwrap(),
        &nsecs
    )
    .is_secure());
}

pub fn test_rfc_6975_supported_algorithms<A: Authority<Lookup = AuthLookup>>(
    authority: A,
    keys: &[DNSKEY],
) {
    // for each key, see that supported algorithms are restricted to that individual key
    for key in keys {
        println!("key algorithm: {}", key.algorithm());

        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A).into();
        let request_info = RequestInfo::new(
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
            TEST_HEADER,
            &query,
        );

        let lookup = block_on(authority.search(
            request_info,
            LookupOptions::for_dnssec(true, SupportedAlgorithms::from(key.algorithm())),
        ))
        .unwrap();

        let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
            .into_iter()
            .partition(|r| r.record_type() == RecordType::A);

        let rrsig_records: Vec<_> = other_records
            .into_iter()
            .cloned()
            .filter_map(|r| Record::<RRSIG>::try_from(r).ok())
            .collect();

        assert!(!rrsig_records.is_empty());
        verify(&a_records, &rrsig_records, &[key.clone()]);
    }
}

pub fn verify(records: &[&Record], rrsig_records: &[Record<RRSIG>], keys: &[DNSKEY]) {
    let record_name = records.first().unwrap().name();
    let record_type = records.first().unwrap().record_type();
    println!("record_name: {record_name}, type: {record_type}");

    // should be signed with all the keys
    assert!(keys.iter().all(|key| rrsig_records
        .iter()
        .map(|rrsig| rrsig.data())
        .filter(|rrsig| rrsig.algorithm() == key.algorithm())
        .filter(|rrsig| rrsig.key_tag() == key.calculate_key_tag().unwrap())
        .filter(|rrsig| rrsig.type_covered() == record_type)
        .any(|rrsig| key
            .verify_rrsig(record_name, DNSClass::IN, rrsig, records)
            .map_err(|e| println!("failed to verify: {e}"))
            .is_ok())));
}

pub fn add_signers<A: DnssecAuthority>(authority: &mut A) -> Vec<DNSKEY> {
    use hickory_server::config::dnssec::*;
    let signer_name = Name::from(authority.origin().to_owned());

    let mut keys = Vec::<DNSKEY>::new();

    // TODO: support RSA signing with ring
    #[cfg(feature = "dnssec-openssl")]
    // rsa
    {
        let key_config = KeyConfig {
            key_path: "../../tests/test-data/test_configs/dnssec/rsa_2048.pem".to_string(),
            password: Some("123456".to_string()),
            algorithm: Algorithm::RSASHA512.to_string(),
            signer_name: Some(signer_name.to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config
            .try_into_signer(signer_name.clone())
            .expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        block_on(authority.add_zone_signing_key(signer)).expect("failed to add signer to zone");
        block_on(authority.secure_zone()).expect("failed to sign zone");
    }

    // // TODO: why are ecdsa tests failing in this context?
    // // ecdsa_p256
    // {
    //     let key_config = KeyConfig {
    //         key_path: "../../tests/test-data/test_configs/dnssec/ecdsa_p256.pem".to_string(),
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
    //         key_path: "../../tests/test-data/test_configs/dnssec/ecdsa_p384.pem".to_string(),
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
            key_path: "../../tests/test-data/test_configs/dnssec/ed25519.pk8".to_string(),
            password: None,
            algorithm: Algorithm::ED25519.to_string(),
            signer_name: Some(signer_name.to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config
            .try_into_signer(signer_name)
            .expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        block_on(authority.add_zone_signing_key(signer)).expect("failed to add signer to zone");
        block_on(authority.secure_zone()).expect("failed to sign zone");
    }

    keys
}

macro_rules! define_dnssec_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let mut authority = crate::$new("../../tests/test-data/test_configs/example.com.zone", module_path!(), stringify!($f));
                let keys = crate::authority_battery::dnssec::add_signers(&mut authority);
                crate::authority_battery::dnssec::$f(authority, &keys);
            }
        )*
    }
}

macro_rules! dnssec_battery {
    ($new:ident) => {
        #[cfg(test)]
        mod dnssec {
            mod $new {
                define_dnssec_test!($new;
                    test_a_lookup,
                    test_soa,
                    test_ns,
                    test_aname_lookup,
                    test_wildcard,
                    test_nsec_nodata,
                    test_nsec_nxdomain_start,
                    test_nsec_nxdomain_middle,
                    test_nsec_nxdomain_wraps_end,
                    test_rfc_6975_supported_algorithms,
                );
            }
        }
    };
}
