#![cfg(feature = "__dnssec")]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use futures_executor::block_on;

use hickory_proto::{
    dnssec::{
        Algorithm, Verifier,
        rdata::{DNSKEY, DNSSECRData, RRSIG},
    },
    op::{Header, MessageType, OpCode, Query},
    rr::{DNSClass, Name, RData, Record, RecordType},
    xfer::Protocol,
};
use hickory_server::{
    server::Request,
    zone_handler::{DnssecZoneHandler, LookupOptions, MessageRequest, ZoneHandler},
};

const TEST_HEADER: &Header = &Header::new(10, MessageType::Query, OpCode::Query);

pub fn test_a_lookup(handler: impl ZoneHandler, keys: &[DNSKEY]) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::A),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::for_dnssec()))
        .0
        .unwrap();

    let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::A);

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(into_rrsig)
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&a_records, &rrsig_records, keys);
}

#[allow(clippy::unreadable_literal)]
pub fn test_soa(handler: impl ZoneHandler, keys: &[DNSKEY]) {
    let lookup = block_on(handler.lookup(
        handler.origin(),
        RecordType::SOA,
        None,
        LookupOptions::for_dnssec(),
    ))
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
        .filter_map(into_rrsig)
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&soa_records, &rrsig_records, keys);
}

pub fn test_ns(handler: impl ZoneHandler, keys: &[DNSKEY]) {
    let lookup = block_on(handler.lookup(
        handler.origin(),
        RecordType::NS,
        None,
        LookupOptions::for_dnssec(),
    ))
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
        .filter_map(into_rrsig)
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&ns_records, &rrsig_records, keys);
}

pub fn test_aname_lookup(handler: impl ZoneHandler, keys: &[DNSKEY]) {
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("aname-chain.example.com.").unwrap(),
                RecordType::A,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::for_dnssec()))
        .0
        .unwrap();

    let (a_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::A);

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(into_rrsig)
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&a_records, &rrsig_records, keys);
}

pub fn test_wildcard(handler: impl ZoneHandler, keys: &[DNSKEY]) {
    // check wildcard lookup
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("www.wildcard.example.com.").unwrap(),
                RecordType::CNAME,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::for_dnssec()))
        .0
        .expect("lookup of www.wildcard.example.com. failed");

    let (cname_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::CNAME);

    assert!(
        cname_records
            .iter()
            .all(|r| *r.name() == Name::from_str("www.wildcard.example.com.").unwrap())
    );

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(into_rrsig)
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&cname_records, &rrsig_records, keys);
}

pub fn test_wildcard_subdomain(handler: impl ZoneHandler, keys: &[DNSKEY]) {
    // check wildcard lookup
    let request = Request::from_message(
        MessageRequest::mock(
            *TEST_HEADER,
            Query::query(
                Name::from_str("subdomain.www.wildcard.example.com.").unwrap(),
                RecordType::CNAME,
            ),
        ),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        Protocol::Udp,
    )
    .unwrap();

    let lookup = block_on(handler.search(&request, LookupOptions::for_dnssec()))
        .0
        .expect("lookup of subdomain.www.wildcard.example.com. failed");

    let (cname_records, other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .partition(|r| r.record_type() == RecordType::CNAME);

    assert!(
        cname_records
            .iter()
            .all(|r| *r.name() == Name::from_str("subdomain.www.wildcard.example.com.").unwrap())
    );

    let rrsig_records: Vec<_> = other_records
        .into_iter()
        .cloned()
        .filter_map(into_rrsig)
        .collect();

    assert!(!rrsig_records.is_empty());
    verify(&cname_records, &rrsig_records, keys);
}

fn into_rrsig(r: Record<RData>) -> Option<Record<RRSIG>> {
    r.map(|data| match data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig),
        _ => None,
    })
}

pub fn test_nsec_nodata(handler: impl ZoneHandler, _: &[DNSKEY]) {
    // this should have a single nsec record that covers the type
    let name = Name::from_str("www.example.com.").unwrap();
    let lookup =
        block_on(handler.nsec_records(&name.clone().into(), LookupOptions::for_dnssec())).unwrap();

    let (nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);

    println!("nsec_records: {nsec_records:?}");

    // there should only be one, and it should match the www.example.com name
    let nsec_text = nsec_records
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(
        nsec_text,
        ["www.example.com. 86400 IN NSEC example.com. A AAAA RRSIG NSEC"]
    );
}

pub fn test_nsec_nxdomain_start(handler: impl ZoneHandler, _: &[DNSKEY]) {
    // tests between the SOA and first record in the zone, where bbb is the first zone record
    let name = Name::from_str("aaa.example.com.").unwrap();
    let lookup =
        block_on(handler.nsec_records(&name.clone().into(), LookupOptions::for_dnssec())).unwrap();

    let (nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);

    println!("nsec_records: {nsec_records:?}");

    // Because the first NSEC record is from the zone apex, a separate NSEC record for the wildcard
    // isn't necessary. That is, `example.com.` -> `alias.example.com.` proves there is no wildcard.
    let nsec_text = nsec_records
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(
        nsec_text,
        ["example.com. 86400 IN NSEC alias.example.com. NS SOA MX RRSIG NSEC DNSKEY ANAME"]
    );
}

pub fn test_nsec_nxdomain_middle(handler: impl ZoneHandler, _: &[DNSKEY]) {
    // follows the first record, nsec should cover between ccc and www, where bbb is the first zone record
    let name = Name::from_str("ccc.example.com.").unwrap();
    let lookup =
        block_on(handler.nsec_records(&name.clone().into(), LookupOptions::for_dnssec())).unwrap();

    let (mut nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);
    nsec_records.sort();

    println!("nsec_records: {nsec_records:?}");

    // one record covers between the names, the other is for the wildcard proof.
    let nsec_text = nsec_records
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(
        nsec_text,
        [
            "example.com. 86400 IN NSEC alias.example.com. NS SOA MX RRSIG NSEC DNSKEY ANAME",
            "bbb.example.com. 86400 IN NSEC this.has.dots.example.com. A RRSIG NSEC",
        ]
    );
}

pub fn test_nsec_nxdomain_wraps_end(handler: impl ZoneHandler, _: &[DNSKEY]) {
    // wraps back to the beginning of the zone, where www is the last zone record
    let name = Name::from_str("zzz.example.com.").unwrap();
    let lookup =
        block_on(handler.nsec_records(&name.clone().into(), LookupOptions::for_dnssec())).unwrap();

    let (mut nsec_records, _other_records): (Vec<_>, Vec<_>) = lookup
        .into_iter()
        .cloned()
        .partition(|r| r.record_type() == RecordType::NSEC);
    nsec_records.sort();

    println!("nsec_records: {nsec_records:?}");

    // one record covers between the names, the other is for the wildcard proof.
    let nsec_text = nsec_records
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(
        nsec_text,
        [
            "example.com. 86400 IN NSEC alias.example.com. NS SOA MX RRSIG NSEC DNSKEY ANAME",
            "www.example.com. 86400 IN NSEC example.com. A AAAA RRSIG NSEC",
        ]
    );
}

pub fn verify(records: &[&Record], rrsig_records: &[Record<RRSIG>], keys: &[DNSKEY]) {
    let record_name = records.first().unwrap().name();
    let record_type = records.first().unwrap().record_type();
    println!("record_name: {record_name}, type: {record_type}");

    // should be signed with all the keys
    assert!(keys.iter().all(|key| {
        rrsig_records
            .iter()
            .map(|rrsig| rrsig.data())
            .filter(|rrsig| rrsig.input().algorithm == key.algorithm())
            .filter(|rrsig| rrsig.input().key_tag == key.calculate_key_tag().unwrap())
            .filter(|rrsig| rrsig.input().type_covered == record_type)
            .any(|rrsig| {
                key.verify_rrsig(record_name, DNSClass::IN, rrsig, records.iter().copied())
                    .map_err(|e| println!("failed to verify: {e}"))
                    .is_ok()
            })
    }));
}

pub fn add_signers<A: DnssecZoneHandler>(handler: &mut A) -> Vec<DNSKEY> {
    use hickory_dns::dnssec::{KeyConfig, KeyPurpose};
    let signer_name = Name::from(handler.origin().to_owned());

    let mut keys = Vec::<DNSKEY>::new();

    // TODO: support RSA signing with ring
    #[cfg(feature = "__dnssec")]
    // rsa
    {
        let key_config = KeyConfig {
            key_path: PathBuf::from("../tests/test-data/test_configs/dnssec/rsa_2048.pk8"),
            algorithm: Algorithm::RSASHA512,
            signer_name: Some(signer_name.to_string()),
            purpose: KeyPurpose::ZoneSigning,
        };

        let signer = key_config
            .try_into_signer(signer_name.clone())
            .expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        block_on(handler.add_zone_signing_key(signer)).expect("failed to add signer to zone");
        block_on(handler.secure_zone()).expect("failed to sign zone");
    }

    // ecdsa_p256
    {
        let key_config = KeyConfig {
            key_path: PathBuf::from("../tests/test-data/test_configs/dnssec/ecdsa_p256.pk8"),
            algorithm: Algorithm::ECDSAP256SHA256,
            signer_name: Some(signer_name.clone().to_string()),
            purpose: KeyPurpose::ZoneSigning,
        };

        let signer = key_config
            .try_into_signer(signer_name.clone())
            .expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        block_on(handler.add_zone_signing_key(signer)).expect("failed to add signer to zone");
        block_on(handler.secure_zone()).expect("failed to sign zone");
    }

    // ecdsa_p384
    {
        let key_config = KeyConfig {
            key_path: PathBuf::from("../tests/test-data/test_configs/dnssec/ecdsa_p384.pk8"),
            algorithm: Algorithm::ECDSAP384SHA384,
            signer_name: Some(signer_name.clone().to_string()),
            purpose: KeyPurpose::ZoneSigning,
        };

        let signer = key_config
            .try_into_signer(signer_name.clone())
            .expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        block_on(handler.add_zone_signing_key(signer)).expect("failed to add signer to zone");
        block_on(handler.secure_zone()).expect("failed to sign zone");
    }

    // ed 25519
    #[cfg(feature = "__dnssec")]
    {
        let key_config = KeyConfig {
            key_path: PathBuf::from("../tests/test-data/test_configs/dnssec/ed25519.pk8"),
            algorithm: Algorithm::ED25519,
            signer_name: Some(signer_name.to_string()),
            purpose: KeyPurpose::ZoneSigning,
        };

        let signer = key_config
            .try_into_signer(signer_name)
            .expect("failed to read key_config");
        keys.push(signer.to_dnskey().expect("failed to create DNSKEY"));
        block_on(handler.add_zone_signing_key(signer)).expect("failed to add signer to zone");
        block_on(handler.secure_zone()).expect("failed to sign zone");
    }

    keys
}

macro_rules! define_dnssec_test {
    ($new:expr; $( $f:ident, )*) => {
        $(
            #[test]
            fn $f () {
                ::test_support::subscribe();
                use std::path::Path;
                let mut handler = $new(&Path::new("../tests/test-data/test_configs/example.com.zone"), module_path!(), stringify!($f));
                let keys = crate::zone_handler_battery::dnssec::add_signers(&mut handler);
                crate::zone_handler_battery::dnssec::$f(handler, &keys);
            }
        )*
    }
}

macro_rules! dnssec_battery {
    ($name:ident, $new:expr) => {
        #[cfg(test)]
        mod dnssec {
            mod $name {
                define_dnssec_test!($new;
                    test_a_lookup,
                    test_soa,
                    test_ns,
                    test_aname_lookup,
                    test_wildcard,
                    test_wildcard_subdomain,
                    test_nsec_nodata,
                    test_nsec_nxdomain_start,
                    test_nsec_nxdomain_middle,
                    test_nsec_nxdomain_wraps_end,
                );
            }
        }
    };
}
