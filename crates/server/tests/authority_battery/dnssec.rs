use std::str::FromStr;

use trust_dns::op::Query;
use trust_dns::rr::dnssec::{Algorithm, SupportedAlgorithms, Verifier};
use trust_dns::rr::{DNSClass, Name, Record, RecordType};
use trust_dns::proto::rr::dnssec::rdata::{DNSSECRecordType, DNSKEY};
use trust_dns_server::authority::Authority;

pub fn test_a_lookup<A: Authority>(authority: A, keys: &[DNSKEY]) {
    let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

    let lookup = authority.search(&query.into(), true, SupportedAlgorithms::new());

    let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::A);

    let (rrsig_records, _other_records): (Vec<_>, Vec<_>) = other_records.into_iter().partition(|r| r.record_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG));

    assert!(!rrsig_records.is_empty());
    verify(&a_records, &rrsig_records, keys);
}

pub fn test_soa<A: Authority>(authority: A, keys: &[DNSKEY]) {
    let lookup = authority.soa_secure(true, SupportedAlgorithms::new());

    let (soa_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::SOA);

    assert_eq!(soa_records.len(), 1);
    
    let soa = soa_records.first().unwrap().rdata().as_soa().unwrap();

    assert_eq!(Name::from_str("trust-dns.org.").unwrap(), *soa.mname());
    assert_eq!(Name::from_str("root.trust-dns.org.").unwrap(), *soa.rname());
    assert!(199609203 < soa.serial()); // serial should be one or more b/c of the signing process
    assert_eq!(28800, soa.refresh());
    assert_eq!(7200, soa.retry());
    assert_eq!(604800, soa.expire());
    assert_eq!(86400, soa.minimum());
      
    let (rrsig_records, _other_records): (Vec<_>, Vec<_>) = other_records.into_iter().partition(|r| r.record_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG));

    assert!(!rrsig_records.is_empty());
    verify(&soa_records, &rrsig_records, keys);
}

pub fn test_ns<A: Authority>(authority: A, keys: &[DNSKEY]) {
    let lookup = authority.ns(true, SupportedAlgorithms::new());

    let (ns_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NS);

    assert_eq!(
        *ns_records.first().unwrap().rdata().as_ns().unwrap(),
        Name::from_str("trust-dns.org.").unwrap()
    );
    

    let (rrsig_records, _other_records): (Vec<_>, Vec<_>) = other_records.into_iter().partition(|r| r.record_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG));

    assert!(!rrsig_records.is_empty());
    verify(&ns_records, &rrsig_records, keys);
}

pub fn test_rfc_6975_supported_algorithms<A: Authority>(authority: A, keys: &[DNSKEY]) {
    // for each key, see that supported algorithms are restricted to that individual key
    for key in keys {
        println!("key algorithm: {}", key.algorithm());

        let query = Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A);

        let lookup = authority.search(&query.into(), true, SupportedAlgorithms::from(key.algorithm()));

        let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
            .into_iter()
            .cloned()
            .partition(|r| r.record_type() == RecordType::A);

        let (rrsig_records, _other_records): (Vec<_>, Vec<_>) = other_records.into_iter().partition(|r| r.record_type() == RecordType::DNSSEC(DNSSECRecordType::RRSIG));

        assert!(!rrsig_records.is_empty());
        verify(&a_records, &rrsig_records, &[key.clone()]);
    }
}

pub fn verify(records: &[Record], rrsig_records: &[Record], keys: &[DNSKEY]) {
    let record_name = records.first().unwrap().name();
    let record_type = records.first().unwrap().record_type();
    println!("record_name: {}", record_name);

    // should be signed with all the keys
    assert!(keys
        .iter()
        .all(|key| rrsig_records
            .iter()
            .filter_map(|rrsig| {
                let rrsig = rrsig.rdata()
                    .as_dnssec()
                    .expect("not DNSSEC")
                    .as_sig()
                    .expect("not RRSIG");
                if rrsig.algorithm() == key.algorithm() {
                    Some(rrsig)
                } else {
                    None
                }
            })
            .filter(|rrsig| rrsig.key_tag() == key.calculate_key_tag().unwrap())
            .filter(|rrsig| rrsig.type_covered() == record_type)
            .any(|rrsig| {
                key.verify_rrsig(
                    record_name,
                    DNSClass::IN,
                    rrsig,
                    records)
                    .map_err(|e| println!("failed to verify: {}", e))
                    .is_ok()
            })
        )
    );
}

pub fn add_signers<A: Authority>(authority: &mut A) -> Vec<DNSKEY> {
    use trust_dns_server::config::dnssec::*;
    let signer_name = Name::from(authority.origin().to_owned());

    let mut keys = Vec::<DNSKEY>::new();

    // TODO: support RSA signing with ring
    #[cfg(feature = "dnssec-openssl")]
    // rsa
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/rsa_2048.pem".to_string(),
            password: Some("123456".to_string()),
            algorithm: Algorithm::RSASHA512.to_string(),
            signer_name: Some(signer_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        authority.add_secure_key(signer).expect("failed to add signer to zone");
        authority.secure_zone().expect("failed to sign zone");
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
    //     authority.add_secure_key(signer).expect("failed to add signer to zone");
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
    //     authority.add_secure_key(signer).expect("failed to add signer to zone");
    //     authority.secure_zone().expect("failed to sign zone");
    // }

    // ed 25519
    #[cfg(feature = "dnssec-ring")]
    {
        let key_config = KeyConfig {
            key_path: "tests/named_test_configs/dnssec/ed25519.pk8".to_string(),
            password: None,
            algorithm: Algorithm::ED25519.to_string(),
            signer_name: Some(signer_name.clone().to_string()),
            is_zone_signing_key: Some(true),
            is_zone_update_auth: Some(false),
        };

        let signer = key_config.try_into_signer(signer_name.clone()).expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        authority.add_secure_key(signer).expect("failed to add signer to zone");
        authority.secure_zone().expect("failed to sign zone");
    }

    keys
}

macro_rules! define_dnssec_test {
    ($new:ident; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                let mut authority = ::$new("tests/named_test_configs/example.com.zone", module_path!(), stringify!($f));
                let keys = ::authority_battery::dnssec::add_signers(&mut authority);
                ::authority_battery::dnssec::$f(authority, &keys);
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
                    test_rfc_6975_supported_algorithms,
                );
            }
        }
    };
}
