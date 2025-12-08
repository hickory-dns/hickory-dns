use std::str::FromStr;

use futures_executor::block_on;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::rdata::{A, AAAA, tlsa::*};
use hickory_proto::rr::*;
use hickory_proto::serialize::txt::*;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, LookupOptions, ZoneHandler, ZoneType};
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

c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com. IN SMIMEA (
    3 0 0
    3082019130820143a003020102021408092db4b8561e4250a828cb97
    274da7e0be5917300506032b6570303d310b30090603550406130244
    45310d300b06035504030c0448756768311f301d06092a864886f70d
    010901161068756768406578616d706c652e636f6d3020170d323531
    3030383038353435395a180f32303735303932363038353435395a30
    3d310b3009060355040613024445310d300b06035504030c04487567
    68311f301d06092a864886f70d010901161068756768406578616d70
    6c652e636f6d302a300506032b6570032100c2b090fac61352f82085
    1c77162d6078817da0cdf08725bddd11d67a305be265a3533051301d
    0603551d0e0416041426df1e20bb73a81eaf15f90db770fd974872db
    11301f0603551d2304183016801426df1e20bb73a81eaf15f90db770
    fd974872db11300f0603551d130101ff040530030101ff300506032b
    65700341009d729b9296728a3ca22d82b11b058cb3fa5239fe0f3ced
    2cbe39b85207d3f9421aae97edf8801d6a242d83b2506ff9474cd588
    6cb893534da3b7f017b9c67004)

_443._tcp.www.example.com. IN TLSA (
      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971)

tech.   3600    in      soa     ns0.centralnic.net.     hostmaster.centralnic.net.      271851  900     1800    6048000 3600
"#;

    let records = Parser::new(ZONE, None, Some(Name::from_str("isi.edu.").unwrap())).parse();
    if let Err(error) = records {
        panic!("failed to parse: {error:?}")
    }

    let (origin, records) = records.unwrap();

    let handler: InMemoryZoneHandler = InMemoryZoneHandler::new(
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
    let lookup = block_on(handler.lookup(
        handler.origin(),
        RecordType::SOA,
        None,
        LookupOptions::default(),
    ))
    .unwrap();

    let soa_record = lookup.iter().next().cloned().unwrap();
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

    let lowercase_record = block_on(handler.lookup(
        &Name::from_str("tech.").unwrap().into(),
        RecordType::SOA,
        None,
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
    let mut ns_records: Vec<Record> = block_on(handler.lookup(
        &Name::from_str("isi.edu.").unwrap().into(),
        RecordType::NS,
        None,
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
    let mut mx_records: Vec<Record> = block_on(handler.lookup(
        &Name::from_str("isi.edu.").unwrap().into(),
        RecordType::MX,
        None,
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
    let a_record: Record = block_on(handler.lookup(
        &Name::from_str("a.isi.edu.").unwrap().into(),
        RecordType::A,
        None,
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
    let aaaa_record: Record = block_on(handler.lookup(
        &Name::from_str("aaaa.isi.edu.").unwrap().into(),
        RecordType::AAAA,
        None,
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
    let short_record: Record = block_on(handler.lookup(
        &Name::from_str("short.isi.edu.").unwrap().into(),
        RecordType::A,
        None,
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
    let mut txt_records: Vec<Record> = block_on(handler.lookup(
        &Name::from_str("a.isi.edu.").unwrap().into(),
        RecordType::TXT,
        None,
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
    let ptr_record: Record = block_on(handler.lookup(
        &Name::from_str("103.0.3.26.in-addr.arpa.").unwrap().into(),
        RecordType::PTR,
        None,
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
        handler.lookup(
            &Name::from_str("_ldap._tcp.service.isi.edu.")
                .unwrap()
                .into(),
            RecordType::SRV,
            None,
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
    let idna_record: Record = block_on(handler.lookup(
        &Name::from_str("rust-❤️-🦀.isi.edu.").unwrap().into(),
        RecordType::A,
        None,
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
    let caa_record: Record = block_on(handler.lookup(
        &Name::parse("nocerts.isi.edu.", None).unwrap().into(),
        RecordType::CAA,
        None,
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

    // SMIMEA
    let smimea_record: Record = block_on(
        handler.lookup(
            &Name::parse(
                "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com.",
                None,
            )
            .unwrap()
            .into(),
            RecordType::SMIMEA,
            None,
            LookupOptions::default(),
        ),
    )
    .unwrap()
    .iter()
    .next()
    .cloned()
    .expect("smimea record not found");
    if let RData::SMIMEA(rdata) = smimea_record.data() {
        assert_eq!(rdata.cert_usage(), CertUsage::DaneEe);
        assert_eq!(rdata.selector(), Selector::Full);
        assert_eq!(rdata.matching(), Matching::Raw);
        assert_eq!(
            rdata.cert_data(),
            &[
                0x30, 0x82, 0x01, 0x91, 0x30, 0x82, 0x01, 0x43, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
                0x14, 0x08, 0x09, 0x2d, 0xb4, 0xb8, 0x56, 0x1e, 0x42, 0x50, 0xa8, 0x28, 0xcb, 0x97,
                0x27, 0x4d, 0xa7, 0xe0, 0xbe, 0x59, 0x17, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44,
                0x45, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x48, 0x75,
                0x67, 0x68, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                0x01, 0x09, 0x01, 0x16, 0x10, 0x68, 0x75, 0x67, 0x68, 0x40, 0x65, 0x78, 0x61, 0x6d,
                0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x35, 0x31,
                0x30, 0x30, 0x38, 0x30, 0x38, 0x35, 0x34, 0x35, 0x39, 0x5a, 0x18, 0x0f, 0x32, 0x30,
                0x37, 0x35, 0x30, 0x39, 0x32, 0x36, 0x30, 0x38, 0x35, 0x34, 0x35, 0x39, 0x5a, 0x30,
                0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45,
                0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x48, 0x75, 0x67,
                0x68, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                0x09, 0x01, 0x16, 0x10, 0x68, 0x75, 0x67, 0x68, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70,
                0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
                0x70, 0x03, 0x21, 0x00, 0xc2, 0xb0, 0x90, 0xfa, 0xc6, 0x13, 0x52, 0xf8, 0x20, 0x85,
                0x1c, 0x77, 0x16, 0x2d, 0x60, 0x78, 0x81, 0x7d, 0xa0, 0xcd, 0xf0, 0x87, 0x25, 0xbd,
                0xdd, 0x11, 0xd6, 0x7a, 0x30, 0x5b, 0xe2, 0x65, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
                0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x26, 0xdf, 0x1e, 0x20, 0xbb,
                0x73, 0xa8, 0x1e, 0xaf, 0x15, 0xf9, 0x0d, 0xb7, 0x70, 0xfd, 0x97, 0x48, 0x72, 0xdb,
                0x11, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
                0x26, 0xdf, 0x1e, 0x20, 0xbb, 0x73, 0xa8, 0x1e, 0xaf, 0x15, 0xf9, 0x0d, 0xb7, 0x70,
                0xfd, 0x97, 0x48, 0x72, 0xdb, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
                0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x05, 0x06, 0x03, 0x2b,
                0x65, 0x70, 0x03, 0x41, 0x00, 0x9d, 0x72, 0x9b, 0x92, 0x96, 0x72, 0x8a, 0x3c, 0xa2,
                0x2d, 0x82, 0xb1, 0x1b, 0x05, 0x8c, 0xb3, 0xfa, 0x52, 0x39, 0xfe, 0x0f, 0x3c, 0xed,
                0x2c, 0xbe, 0x39, 0xb8, 0x52, 0x07, 0xd3, 0xf9, 0x42, 0x1a, 0xae, 0x97, 0xed, 0xf8,
                0x80, 0x1d, 0x6a, 0x24, 0x2d, 0x83, 0xb2, 0x50, 0x6f, 0xf9, 0x47, 0x4c, 0xd5, 0x88,
                0x6c, 0xb8, 0x93, 0x53, 0x4d, 0xa3, 0xb7, 0xf0, 0x17, 0xb9, 0xc6, 0x70, 0x04
            ]
        );
    } else {
        panic!();
    }

    // TLSA
    let tlsa_record: Record = block_on(
        handler.lookup(
            &Name::parse("_443._tcp.www.example.com.", None)
                .unwrap()
                .into(),
            RecordType::TLSA,
            None,
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

    if let Err(error) = records {
        panic!("failed to parse: {error:?}")
    }

    let (origin, records) = records.unwrap();

    assert!(
        InMemoryZoneHandler::<TokioRuntimeProvider>::new(
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

    if let Err(error) = records {
        panic!("failed to parse: {error:?}")
    }

    let (origin, records) = records.unwrap();

    assert!(
        InMemoryZoneHandler::<TokioRuntimeProvider>::new(
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

    if let Err(error) = records {
        panic!("failed to parse: {error:?}")
    }

    let (origin, records) = records.unwrap();

    assert!(
        InMemoryZoneHandler::<TokioRuntimeProvider>::new(
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

    if let Err(error) = records {
        panic!("failed to parse: {error:?}")
    }

    let (_, records) = records.unwrap();
    let key = RrKey::new(LowerName::from(Name::root()), RecordType::NS);

    assert!(records.contains_key(&key));
    assert_eq!(records[&key].dns_class(), DNSClass::IN)
}
