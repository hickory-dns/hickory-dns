#![cfg(feature = "dnssec")]

use std::sync::Arc;

use hickory_proto::dnssec::rdata::{DNSKEY, DS};
use hickory_proto::dnssec::{Algorithm, DigestType, PublicKeyBuf};
use hickory_proto::rr::Name;

#[test]
#[allow(deprecated)]
fn test_dnskey_display() {
    let dnskey = DNSKEY::new(
        true,
        false,
        false,
        Algorithm::RSASHA1,
        Arc::new(PublicKeyBuf::new(
            include_bytes!("../test-data/rfc4034-2.3.key").to_vec(),
        )),
    );
    let result = format!("{dnskey}");
    let exp_result = include_str!("../test-data/rfc4034-2.3.rdata");
    assert_eq!(result, exp_result);

    let dnskey = DNSKEY::new(
        true,
        false,
        false,
        Algorithm::RSASHA1,
        Arc::new(PublicKeyBuf::new(
            include_bytes!("../test-data/rfc4034-5.4.key").to_vec(),
        )),
    );
    let result = format!("{dnskey}");
    let exp_result = include_str!("../test-data/rfc4034-5.4.rdata");
    assert_eq!(result, exp_result);
}

#[cfg(any(feature = "dnssec-ring", feature = "dnssec-openssl"))]
#[test]
#[allow(deprecated)]
fn test_ds_display() {
    let dnskey = DNSKEY::new(
        true,
        false,
        false,
        Algorithm::RSASHA1,
        Arc::new(PublicKeyBuf::new(
            include_bytes!("../test-data/rfc4034-5.4.key").to_vec(),
        )),
    );
    let digest = dnskey
        .to_digest(
            &Name::parse("dskey.example.com.", None).unwrap(),
            DigestType::SHA1,
        )
        .unwrap();
    let ds = DS::new(
        dnskey.calculate_key_tag().unwrap(),
        dnskey.algorithm(),
        DigestType::SHA1,
        digest.as_ref().to_vec(),
    );
    let result = format!("{ds}");
    let exp_result = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118";
    assert_eq!(result, exp_result);
}
