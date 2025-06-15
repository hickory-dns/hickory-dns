use std::str::FromStr;

use futures_executor::block_on;

use hickory_proto::rr::rdata::{A, AAAA, tlsa::*};
use hickory_proto::rr::*;
use hickory_proto::serialize::txt::*;
use hickory_server::authority::{Authority, AxfrPolicy, LookupOptions, ZoneType};
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::store::in_memory::InMemoryAuthority;
use test_support::subscribe;

// TODO: split this test up to test each thing separately
#[test]
#[allow(clippy::cognitive_complexity)]
fn test_zone() {
    subscribe();

    const ZONE: &str = r#"
@   IN  SOA     venera      action\.domains (
                            20     ; SERIAL
                            7200   ; REFRESH
                            600    ; RETRY
                            3600000; EXPIRE
                            60)    ; MINIMUM

        NS      a.isi.edu.
        NS      venera
        NS      vaxa
        MX  10  venera
        MX  20  vaxa

a       A       26.3.0.103
        TXT     I am a txt record
        TXT     I am another txt record
        TXT     "I am a different" "txt record"
        TXT     key=val

aaaa    AAAA    4321:0:1:2:3:4:567:89ab
alias   CNAME   a
103.0.3.26.IN-ADDR.ARPA.   PTR a
b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA. PTR aaaa

_ldap._tcp.service SRV 1 2 3 short

rust-❤️-🦀    A  192.0.2.1

short 70     A  26.3.0.104
venera       A  10.1.0.52
             A  128.9.0.32

nocerts      CAA 0 issue ";"
certs        CAA 0 issuewild "example.net"

_443._tcp.www.example.com. IN TLSA (
      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971)

tech.   3600    in      soa     ns0.centralnic.net.     hostmaster.centralnic.net.      271851  900     1800    6048000 3600
"#;

    let records = Parser::new(ZONE, None, Some(Name::from_str("isi.edu.").unwrap())).parse();
    if records.is_err() {
        panic!("failed to parse: {:?}", records.err())
    }

    let (origin, records) = records.unwrap();

    let authority = InMemoryAuthority::new(
        origin,
        records,
        ZoneType::Primary,
        AxfrPolicy::Deny,
        #[cfg(feature = "__dnssec")]
        Some(NxProofKind::Nsec),
    )
    .unwrap();
    // not validating everything, just one of each...

    // SOA
    let soa_record = block_on(authority.soa())
        .unwrap()
        .iter()
        .next()
        .cloned()
        .unwrap();
    assert_eq!(RecordType::SOA, soa_record.record_type());
    assert_eq!(&Name::from_str("isi.edu.").unwrap(), soa_record.name()); // i.e. the origin or domain
    assert_eq!(3_600_000, soa_record.ttl());
    assert_eq!(DNSClass::IN, soa_record.dns_class());
    if let RData::SOA(soa) = soa_record.data() {
        // this should all be lowercased
        assert_eq!(&Name::from_str("venera.isi.edu.").unwrap(), soa.mname());
        assert_eq!(
            &Name::from_str("action\\.domains.isi.edu.").unwrap(),
            soa.rname()
        );
        assert_eq!(20, soa.serial());
        assert_eq!(7200, soa.refresh());
        assert_eq!(600, soa.retry());
        assert_eq!(3_600_000, soa.expire());
        assert_eq!(60, soa.minimum());
    } else {
        panic!("Not an SOA record!!!") // valid panic, test code
    }

    let lowercase_record = block_on(authority.lookup(
        &Name::from_str("tech.").unwrap().into(),
        RecordType::SOA,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    assert_eq!(&Name::from_str("tech.").unwrap(), lowercase_record.name());
    assert_eq!(DNSClass::IN, lowercase_record.dns_class());
    if let RData::SOA(lower_soa) = lowercase_record.data() {
        assert_eq!(
            &Name::from_str("ns0.centralnic.net.").unwrap(),
            lower_soa.mname()
        );
        assert_eq!(
            &Name::from_str("hostmaster.centralnic.net.").unwrap(),
            lower_soa.rname()
        );
        assert_eq!(271851, lower_soa.serial());
        assert_eq!(900, lower_soa.refresh());
        assert_eq!(1800, lower_soa.retry());
        assert_eq!(6_048_000, lower_soa.expire());
        assert_eq!(3_600, lower_soa.minimum());
    } else {
        panic!("Not an SOA record!!!") // valid panic, test code
    }

    // NS
    let mut ns_records: Vec<Record> = block_on(authority.lookup(
        &Name::from_str("isi.edu.").unwrap().into(),
        RecordType::NS,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .cloned()
    .collect();
    let mut compare = vec![
        // this is cool, zip up the expected results... works as long as the order is good.
        Name::from_str("a.isi.edu.").unwrap(),
        Name::from_str("venera.isi.edu.").unwrap(),
        Name::from_str("vaxa.isi.edu.").unwrap(),
    ];

    compare.sort();
    ns_records.sort();
    let compare = ns_records.iter().zip(compare);

    for (record, name) in compare {
        assert_eq!(&Name::from_str("isi.edu.").unwrap(), record.name());
        assert_eq!(60, record.ttl()); // TODO: should this be minimum or expire?
        assert_eq!(DNSClass::IN, record.dns_class());
        assert_eq!(RecordType::NS, record.record_type());
        if let RData::NS(nsdname) = record.data() {
            assert_eq!(name, nsdname.0);
        } else {
            panic!("Not an NS record!!!") // valid panic, test code
        }
    }

    // MX
    let mut mx_records: Vec<Record> = block_on(authority.lookup(
        &Name::from_str("isi.edu.").unwrap().into(),
        RecordType::MX,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .cloned()
    .collect();
    let mut compare = vec![
        (10, Name::from_str("venera.isi.edu.").unwrap()),
        (20, Name::from_str("vaxa.isi.edu.").unwrap()),
    ];

    compare.sort();
    mx_records.sort();
    let compare = mx_records.iter().zip(compare);

    for (record, (num, name)) in compare {
        assert_eq!(&Name::from_str("isi.edu.").unwrap(), record.name());
        assert_eq!(60, record.ttl()); // TODO: should this be minimum or expire?
        assert_eq!(DNSClass::IN, record.dns_class());
        assert_eq!(RecordType::MX, record.record_type());
        if let RData::MX(rdata) = record.data() {
            assert_eq!(num, rdata.preference());
            assert_eq!(&name, rdata.exchange());
        } else {
            panic!("Not an NS record!!!") // valid panic, test code
        }
    }

    // A
    let a_record: Record = block_on(authority.lookup(
        &Name::from_str("a.isi.edu.").unwrap().into(),
        RecordType::A,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    assert_eq!(&Name::from_str("a.isi.edu.").unwrap(), a_record.name());
    assert_eq!(60, a_record.ttl()); // TODO: should this be minimum or expire?
    assert_eq!(DNSClass::IN, a_record.dns_class());
    assert_eq!(RecordType::A, a_record.record_type());
    if let RData::A(address) = a_record.data() {
        assert_eq!(&A::new(26u8, 3u8, 0u8, 103u8), address);
    } else {
        panic!("Not an A record!!!") // valid panic, test code
    }

    // AAAA
    let aaaa_record: Record = block_on(authority.lookup(
        &Name::from_str("aaaa.isi.edu.").unwrap().into(),
        RecordType::AAAA,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    assert_eq!(
        &Name::from_str("aaaa.isi.edu.").unwrap(),
        aaaa_record.name()
    );
    if let RData::AAAA(address) = aaaa_record.data() {
        assert_eq!(&AAAA::from_str("4321:0:1:2:3:4:567:89ab").unwrap(), address);
    } else {
        panic!("Not a AAAA record!!!") // valid panic, test code
    }

    // SHORT
    let short_record: Record = block_on(authority.lookup(
        &Name::from_str("short.isi.edu.").unwrap().into(),
        RecordType::A,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    assert_eq!(
        &Name::from_str("short.isi.edu.").unwrap(),
        short_record.name()
    );
    assert_eq!(70, short_record.ttl());
    if let RData::A(address) = short_record.data() {
        assert_eq!(&A::new(26u8, 3u8, 0u8, 104u8), address);
    } else {
        panic!("Not an A record!!!") // valid panic, test code
    }

    // TXT
    let mut txt_records: Vec<Record> = block_on(authority.lookup(
        &Name::from_str("a.isi.edu.").unwrap().into(),
        RecordType::TXT,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .cloned()
    .collect();
    let compare: Vec<Vec<Box<[u8]>>> = vec![
        vec![b"I" as &[u8], b"am", b"a", b"txt", b"record"]
            .into_iter()
            .map(Box::from)
            .collect(),
        vec![b"I" as &[u8], b"am", b"another", b"txt", b"record"]
            .into_iter()
            .map(Box::from)
            .collect(),
        vec![b"key=val" as &[u8]]
            .into_iter()
            .map(Box::from)
            .collect(),
        vec![b"I am a different" as &[u8], b"txt record"]
            .into_iter()
            .map(Box::from)
            .collect(),
    ];

    txt_records.sort();

    println!("compare: {compare:#?}");
    println!("txt_records: {txt_records:#?}");

    let compare = txt_records.iter().zip(compare);

    for (record, vector) in compare {
        if let RData::TXT(rdata) = record.data() {
            assert_eq!(&vector as &[Box<[u8]>], rdata.txt_data());
        } else {
            panic!("Not a TXT record!!!") // valid panic, test code
        }
    }

    // PTR
    let ptr_record: Record = block_on(authority.lookup(
        &Name::from_str("103.0.3.26.in-addr.arpa.").unwrap().into(),
        RecordType::PTR,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    if let RData::PTR(ptrdname) = ptr_record.data() {
        assert_eq!(Name::from_str("a.isi.edu.").unwrap(), ptrdname.0);
    } else {
        panic!("Not a PTR record!!!") // valid panic, test code
    }

    // SRV
    let srv_record: Record = block_on(
        authority.lookup(
            &Name::from_str("_ldap._tcp.service.isi.edu.")
                .unwrap()
                .into(),
            RecordType::SRV,
            LookupOptions::default(),
        ),
    )
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    if let RData::SRV(rdata) = srv_record.data() {
        assert_eq!(rdata.priority(), 1);
        assert_eq!(rdata.weight(), 2);
        assert_eq!(rdata.port(), 3);
        assert_eq!(rdata.target(), &Name::from_str("short.isi.edu.").unwrap());
    } else {
        panic!("Not an SRV record!!!") // valid panic, test code
    }

    // IDNA name: rust-❤️-🦀    A  192.0.2.1
    let idna_record: Record = block_on(authority.lookup(
        &Name::from_str("rust-❤️-🦀.isi.edu.").unwrap().into(),
        RecordType::A,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .unwrap();
    assert_eq!(
        &Name::from_str("rust-❤️-🦀.isi.edu.").unwrap(),
        idna_record.name()
    );
    if let RData::A(address) = idna_record.data() {
        assert_eq!(&A::new(192u8, 0u8, 2u8, 1u8), address);
    } else {
        panic!("Not an A record!!!") // valid panic, test code
    }

    // CAA
    let caa_record: Record = block_on(authority.lookup(
        &Name::parse("nocerts.isi.edu.", None).unwrap().into(),
        RecordType::CAA,
        LookupOptions::default(),
    ))
    .unwrap()
    .iter()
    .next()
    .cloned()
    .expect("nocerts not found");
    if let RData::CAA(rdata) = caa_record.data() {
        assert!(!rdata.issuer_critical());
        rdata.value_as_issue().unwrap();
    } else {
        panic!();
    }

    // TLSA
    let tlsa_record: Record = block_on(
        authority.lookup(
            &Name::parse("_443._tcp.www.example.com.", None)
                .unwrap()
                .into(),
            RecordType::TLSA,
            LookupOptions::default(),
        ),
    )
    .unwrap()
    .iter()
    .next()
    .cloned()
    .expect("tlsa record not found");
    if let RData::TLSA(rdata) = tlsa_record.data() {
        assert_eq!(rdata.cert_usage(), CertUsage::PkixTa);
        assert_eq!(rdata.selector(), Selector::Full);
        assert_eq!(rdata.matching(), Matching::Sha256);
        assert_eq!(
            rdata.cert_data(),
            &[
                210, 171, 222, 36, 13, 124, 211, 238, 107, 75, 40, 197, 77, 240, 52, 185, 121, 131,
                161, 209, 110, 138, 65, 14, 69, 97, 203, 16, 102, 24, 233, 113
            ]
        );
    } else {
        panic!();
    }
}

#[test]
fn test_bad_cname_at_soa() {
    subscribe();

    const ZONE: &str = r"
@   IN  SOA     venera      action\.domains (
                            20     ; SERIAL
                            7200   ; REFRESH
                            600    ; RETRY
                            3600000; EXPIRE
                            60)    ; MINIMUM

        CNAME   a
a       A       127.0.0.1
";

    let records = Parser::new(ZONE, None, Some(Name::from_str("isi.edu").unwrap())).parse();

    if records.is_err() {
        panic!("failed to parse: {:?}", records.err())
    }

    let (origin, records) = records.unwrap();

    assert!(
        InMemoryAuthority::new(
            origin,
            records,
            ZoneType::Primary,
            AxfrPolicy::Deny,
            #[cfg(feature = "__dnssec")]
            Some(NxProofKind::Nsec),
        )
        .is_err()
    );
}

#[test]
fn test_bad_cname_at_a() {
    subscribe();

    const ZONE: &str = r"
@   IN  SOA     venera      action\.domains (
                            20     ; SERIAL
                            7200   ; REFRESH
                            600    ; RETRY
                            3600000; EXPIRE
                            60)    ; MINIMUM

a       CNAME   b
a       A       127.0.0.1
b       A       127.0.0.2
";

    let records = Parser::new(ZONE, None, Some(Name::from_str("isi.edu").unwrap())).parse();

    if records.is_err() {
        panic!("failed to parse: {:?}", records.err())
    }

    let (origin, records) = records.unwrap();

    assert!(
        InMemoryAuthority::new(
            origin,
            records,
            ZoneType::Primary,
            AxfrPolicy::Deny,
            #[cfg(feature = "__dnssec")]
            Some(NxProofKind::Nsec),
        )
        .is_err()
    );
}

#[test]
fn test_aname_at_soa() {
    subscribe();

    const ZONE: &str = r"
@   IN  SOA     venera      action\.domains (
                            20     ; SERIAL
                            7200   ; REFRESH
                            600    ; RETRY
                            3600000; EXPIRE
                            60)    ; MINIMUM

        ANAME   a
a       A       127.0.0.1
";

    let records = Parser::new(ZONE, None, Some(Name::from_str("isi.edu").unwrap())).parse();

    if records.is_err() {
        panic!("failed to parse: {:?}", records.err())
    }

    let (origin, records) = records.unwrap();

    assert!(
        InMemoryAuthority::new(
            origin,
            records,
            ZoneType::Primary,
            AxfrPolicy::Deny,
            #[cfg(feature = "__dnssec")]
            Some(NxProofKind::Nsec),
        )
        .is_ok()
    );
}

#[test]
fn test_named_root() {
    subscribe();

    const ZONE: &str = r"
.                        3600000      NS    A.ROOT-SERVERS.NET.
";

    let records = Parser::new(ZONE, None, Some(Name::root())).parse();

    if records.is_err() {
        panic!("failed to parse: {:?}", records.err())
    }

    let (_, records) = records.unwrap();
    let key = RrKey::new(LowerName::from(Name::root()), RecordType::NS);

    assert!(records.contains_key(&key));
    assert_eq!(records[&key].dns_class(), DNSClass::IN)
}
