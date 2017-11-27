extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_server;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use trust_dns::rr::*;
use trust_dns::rr::dnssec::*;
use trust_dns::serialize::txt::*;
use trust_dns_proto::rr::rdata::tlsa::*;
use trust_dns_server::authority::*;


#[test]
fn test_string() {
    let lexer = Lexer::new(
        "@   IN  SOA     venera      action\\.domains (
                               \
                            20     ; SERIAL
                               7200   ; REFRESH
                               \
                            600    ; RETRY
                               3600000; EXPIRE
                               \
                            60)    ; MINIMUM

      NS      a.isi.edu.
      NS      venera
      \
                            NS      vaxa
      MX      10      venera
      MX      20      vaxa

\
                            a       A       26.3.0.103
        TXT     I am a txt record
        \
                            TXT     I am another txt record
        TXT     \"I am a different\" \
                            \"txt record\"
        TXT     key=val
aaaa    AAAA    \
                            4321:0:1:2:3:4:567:89ab
alias   CNAME   a
103.0.3.26.IN-ADDR.ARPA.   \
                            PTR a
b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.\
                            4.IP6.ARPA. PTR aaaa

_ldap._tcp.service SRV 1 2 3 short

short 70 A      \
                            26.3.0.104
venera  A       10.1.0.52
      A       128.9.0.32

nocerts       CAA 0 issue \";\"
certs         CAA 0 issuewild \"example.net\"

_443._tcp.www.example.com. IN TLSA (
      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971 )
",
    );

    let records = Parser::new().parse(lexer, Some(Name::from_labels(vec!["isi", "edu"])));
    if records.is_err() {
        panic!("failed to parse: {:?}", records.err())
    }

    let (origin, records) = records.unwrap();
    let authority = Authority::new(origin, records, ZoneType::Master, false, false);

    // not validating everything, just one of each...

    // SOA
    let soa_record = authority.soa().unwrap().first().cloned().unwrap();
    assert_eq!(RecordType::SOA, soa_record.rr_type());
    assert_eq!(&Name::from_labels(vec!["isi", "edu"]), soa_record.name()); // i.e. the origin or domain
    assert_eq!(3600000, soa_record.ttl());
    assert_eq!(DNSClass::IN, soa_record.dns_class());
    if let RData::SOA(ref soa) = *soa_record.rdata() {
        // this should all be lowercased
        assert_eq!(
            &Name::from_labels(vec!["venera", "isi", "edu"]),
            soa.mname()
        );
        assert_eq!(
            &Name::from_labels(vec!["action.domains", "isi", "edu"]),
            soa.rname()
        );
        assert_eq!(20, soa.serial());
        assert_eq!(7200, soa.refresh());
        assert_eq!(600, soa.retry());
        assert_eq!(3600000, soa.expire());
        assert_eq!(60, soa.minimum());
    } else {
        panic!("Not an SOA record!!!") // valid panic, test code
    }

    // NS
    let mut ns_records: Vec<&Record> = authority
        .lookup(
            &Name::from_labels(vec!["isi", "edu"]),
            RecordType::NS,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap();
    let mut compare = vec![
        // this is cool, zip up the expected results... works as long as the order is good.
        Name::from_labels(vec!["a", "isi", "edu"]),
        Name::from_labels(vec!["venera", "isi", "edu"]),
        Name::from_labels(vec!["vaxa", "isi", "edu"]),
    ];

    compare.sort();
    ns_records.sort();
    let compare = ns_records.iter().zip(compare);

    for (record, ref name) in compare {
        assert_eq!(&Name::from_labels(vec!["isi", "edu"]), record.name());
        assert_eq!(60, record.ttl()); // TODO: should this be minimum or expire?
        assert_eq!(DNSClass::IN, record.dns_class());
        assert_eq!(RecordType::NS, record.rr_type());
        if let RData::NS(ref nsdname) = *record.rdata() {
            assert_eq!(name, nsdname);
        } else {
            panic!("Not an NS record!!!") // valid panic, test code
        }
    }

    // MX
    let mut mx_records: Vec<&Record> = authority
        .lookup(
            &Name::from_labels(vec!["isi", "edu"]),
            RecordType::MX,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap();
    let mut compare = vec![
        (10, Name::from_labels(vec!["venera", "isi", "edu"])),
        (20, Name::from_labels(vec!["vaxa", "isi", "edu"])),
    ];

    compare.sort();
    mx_records.sort();
    let compare = mx_records.iter().zip(compare);


    for (record, (num, ref name)) in compare {
        assert_eq!(&Name::from_labels(vec!["isi", "edu"]), record.name());
        assert_eq!(60, record.ttl()); // TODO: should this be minimum or expire?
        assert_eq!(DNSClass::IN, record.dns_class());
        assert_eq!(RecordType::MX, record.rr_type());
        if let RData::MX(ref rdata) = *record.rdata() {
            assert_eq!(num, rdata.preference());
            assert_eq!(name, rdata.exchange());
        } else {
            panic!("Not an NS record!!!") // valid panic, test code
        }
    }

    // A
    let a_record: &Record = authority
        .lookup(
            &Name::from_labels(vec!["a", "isi", "edu"]),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    assert_eq!(&Name::from_labels(vec!["a", "isi", "edu"]), a_record.name());
    assert_eq!(60, a_record.ttl()); // TODO: should this be minimum or expire?
    assert_eq!(DNSClass::IN, a_record.dns_class());
    assert_eq!(RecordType::A, a_record.rr_type());
    if let RData::A(ref address) = *a_record.rdata() {
        assert_eq!(&Ipv4Addr::new(26u8, 3u8, 0u8, 103u8), address);
    } else {
        panic!("Not an A record!!!") // valid panic, test code
    }

    // AAAA
    let aaaa_record: &Record = authority
        .lookup(
            &Name::from_labels(vec!["aaaa", "isi", "edu"]),
            RecordType::AAAA,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    assert_eq!(
        &Name::from_labels(vec!["aaaa", "isi", "edu"]),
        aaaa_record.name()
    );
    if let RData::AAAA(ref address) = *aaaa_record.rdata() {
        assert_eq!(
            &Ipv6Addr::from_str("4321:0:1:2:3:4:567:89ab").unwrap(),
            address
        );
    } else {
        panic!("Not a AAAA record!!!") // valid panic, test code
    }

    // SHORT
    let short_record: &Record = authority
        .lookup(
            &Name::from_labels(vec!["short", "isi", "edu"]),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    assert_eq!(
        &Name::from_labels(vec!["short", "isi", "edu"]),
        short_record.name()
    );
    assert_eq!(70, short_record.ttl());
    if let RData::A(ref address) = *short_record.rdata() {
        assert_eq!(&Ipv4Addr::new(26u8, 3u8, 0u8, 104u8), address);
    } else {
        panic!("Not an A record!!!") // valid panic, test code
    }

    // TXT
    let mut txt_records: Vec<&Record> = authority
        .lookup(
            &Name::from_labels(vec!["a", "isi", "edu"]),
            RecordType::TXT,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap();
    let compare = vec![
        vec![
            "I".to_string(),
            "am".to_string(),
            "a".to_string(),
            "txt".to_string(),
            "record".to_string(),
        ],
        vec![
            "I".to_string(),
            "am".to_string(),
            "another".to_string(),
            "txt".to_string(),
            "record".to_string(),
        ],
        vec!["key=val".to_string()],
        vec!["I am a different".to_string(), "txt record".to_string()],
    ];

    txt_records.sort();

    println!("compare: {:#?}", compare);
    println!("txt_records: {:#?}", txt_records);

    let compare = txt_records.iter().zip(compare);


    for (record, ref vector) in compare {
        if let RData::TXT(ref rdata) = *record.rdata() {
            assert_eq!(vector as &[String], rdata.txt_data());
        } else {
            panic!("Not a TXT record!!!") // valid panic, test code
        }
    }

    // PTR
    let ptr_record: &Record = authority
        .lookup(
            &Name::from_labels(vec!["103", "0", "3", "26", "in-addr", "arpa"]),
            RecordType::PTR,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    if let RData::PTR(ref ptrdname) = *ptr_record.rdata() {
        assert_eq!(&Name::from_labels(vec!["a", "isi", "edu"]), ptrdname);
    } else {
        panic!("Not a PTR record!!!") // valid panic, test code
    }

    // SRV
    let srv_record: &Record = authority
        .lookup(
            &Name::from_labels(vec!["_ldap", "_tcp", "service", "isi", "edu"]),
            RecordType::SRV,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    if let RData::SRV(ref rdata) = *srv_record.rdata() {
        assert_eq!(rdata.priority(), 1);
        assert_eq!(rdata.weight(), 2);
        assert_eq!(rdata.port(), 3);
        assert_eq!(
            rdata.target(),
            &Name::from_labels(vec!["short", "isi", "edu"])
        );
    } else {
        panic!("Not an SRV record!!!") // valid panic, test code
    }

    // CAA
    let caa_record: &Record = authority
        .lookup(
            &Name::parse("nocerts.isi.edu.", None).unwrap(),
            RecordType::CAA,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .expect("nocerts not found");
    if let RData::CAA(ref rdata) = *caa_record.rdata() {
        assert!(!rdata.issuer_critical());
        assert!(rdata.tag().is_issue());
        assert!(rdata.value().is_issuer());
    } else {
        assert!(false);
    }

    // TLSA
    let tlsa_record: &Record = authority
        .lookup(
            &Name::parse("_443._tcp.www.example.com.", None).unwrap(),
            RecordType::TLSA,
            false,
            SupportedAlgorithms::new(),
        )
        .unwrap()
        .first()
        .cloned()
        .expect("tlsa record not found");

    if let RData::TLSA(ref rdata) = *tlsa_record.rdata() {
        assert_eq!(*rdata.cert_usage(), CertUsage::CA);
        assert_eq!(*rdata.selector(), Selector::Full);
        assert_eq!(*rdata.matching(), Matching::Sha256);
        assert_eq!(
            rdata.cert_data(),
            &[
                210,
                171,
                222,
                36,
                13,
                124,
                211,
                238,
                107,
                75,
                40,
                197,
                77,
                240,
                52,
                185,
                121,
                131,
                161,
                209,
                110,
                138,
                65,
                14,
                69,
                97,
                203,
                16,
                102,
                24,
                233,
                113
            ]
        );
    } else {
        assert!(false);
    }
}
