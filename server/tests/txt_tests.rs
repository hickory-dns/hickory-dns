extern crate trust_dns;
extern crate trust_dns_server;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use trust_dns::rr::*;
use trust_dns::rr::dnssec::*;
use trust_dns::serialize::txt::*;
use trust_dns_server::authority::*;



#[test]
fn test_string() {
  let lexer = Lexer::new("@   IN  SOA     venera      action\\.domains (
                               20     ; SERIAL
                               7200   ; REFRESH
                               600    ; RETRY
                               3600000; EXPIRE
                               60)    ; MINIMUM

      NS      a.isi.edu.
      NS      venera
      NS      vaxa
      MX      10      venera
      MX      20      vaxa

a       A       26.3.0.103
        TXT     I am a txt record
        TXT     I am another txt record
        TXT     \"I am a different\" \"txt record\"
        TXT     key=val
aaaa    AAAA    4321:0:1:2:3:4:567:89ab
alias   CNAME   a
103.0.3.26.IN-ADDR.ARPA.   PTR a
b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA. PTR aaaa

_ldap._tcp.service SRV 1 2 3 short

short 70 A      26.3.0.104
venera  A       10.1.0.52
      A       128.9.0.32");

  let records = Parser::new().parse(lexer, Some(Name::new().label("isi").label("edu")));
  if records.is_err() { panic!("failed to parse: {:?}", records.err()) }

  let (origin, records) = records.unwrap();
  let authority = Authority::new(origin, records, ZoneType::Master, false, false);

  // not validating everything, just one of each...

  // SOA
  let soa_record = authority.get_soa().unwrap();
  assert_eq!(RecordType::SOA, soa_record.get_rr_type());
  assert_eq!(&Name::new().label("isi").label("edu"), soa_record.get_name()); // i.e. the origin or domain
  assert_eq!(3600000, soa_record.get_ttl());
  assert_eq!(DNSClass::IN, soa_record.get_dns_class());
  if let RData::SOA(ref soa) = *soa_record.get_rdata() {
    // this should all be lowercased
    assert_eq!(&Name::new().label("venera").label("isi").label("edu"), soa.get_mname());
    assert_eq!(&Name::new().label("action.domains").label("isi").label("edu"), soa.get_rname());
    assert_eq!(20, soa.get_serial());
    assert_eq!(7200, soa.get_refresh());
    assert_eq!(600, soa.get_retry());
    assert_eq!(3600000, soa.get_expire());
    assert_eq!(60, soa.get_minimum());
  } else {
    panic!("Not an SOA record!!!") // valid panic, test code
  }

  // NS
  let mut ns_records: Vec<&Record> = authority.lookup(&Name::with_labels(vec!["isi".into(),"edu".into()]), RecordType::NS, false, SupportedAlgorithms::new());
  let mut compare = vec![  // this is cool, zip up the expected results... works as long as the order is good.
    Name::new().label("a").label("isi").label("edu"),
    Name::new().label("venera").label("isi").label("edu"),
    Name::new().label("vaxa").label("isi").label("edu")
    ];

  compare.sort();
  ns_records.sort();
  let compare = ns_records.iter().zip(compare);

  for (record, ref name) in compare {
    assert_eq!(&Name::with_labels(vec!["isi".into(),"edu".into()]), record.get_name());
    assert_eq!(60, record.get_ttl()); // TODO: should this be minimum or expire?
    assert_eq!(DNSClass::IN, record.get_dns_class());
    assert_eq!(RecordType::NS, record.get_rr_type());
    if let RData::NS( ref nsdname ) = *record.get_rdata() {
      assert_eq!(name, nsdname);
    } else {
      panic!("Not an NS record!!!") // valid panic, test code
    }
  }

  // MX
  let mut mx_records: Vec<&Record> = authority.lookup(&Name::new().label("isi").label("edu"), RecordType::MX, false, SupportedAlgorithms::new());
  let mut compare = vec![
    (10, Name::new().label("venera").label("isi").label("edu")),
    (20, Name::new().label("vaxa").label("isi").label("edu")),
    ];

  compare.sort();
  mx_records.sort();
  let compare = mx_records.iter().zip(compare);


  for (record, (num, ref name)) in compare {
    assert_eq!(&Name::new().label("isi").label("edu"), record.get_name());
    assert_eq!(60, record.get_ttl()); // TODO: should this be minimum or expire?
    assert_eq!(DNSClass::IN, record.get_dns_class());
    assert_eq!(RecordType::MX, record.get_rr_type());
    if let RData::MX(ref rdata) = *record.get_rdata() {
      assert_eq!(num, rdata.get_preference());
      assert_eq!(name, rdata.get_exchange());
    } else {
      panic!("Not an NS record!!!") // valid panic, test code
    }
  }

  // A
  let a_record: &Record = authority.lookup(&Name::new().label("a").label("isi").label("edu"), RecordType::A, false, SupportedAlgorithms::new()).first().cloned().unwrap();
  assert_eq!(&Name::new().label("a").label("isi").label("edu"), a_record.get_name());
  assert_eq!(60, a_record.get_ttl()); // TODO: should this be minimum or expire?
  assert_eq!(DNSClass::IN, a_record.get_dns_class());
  assert_eq!(RecordType::A, a_record.get_rr_type());
  if let RData::A(ref address) = *a_record.get_rdata() {
    assert_eq!(&Ipv4Addr::new(26u8,3u8,0u8,103u8), address);
  } else {
    panic!("Not an A record!!!") // valid panic, test code
  }

  // AAAA
  let aaaa_record: &Record = authority.lookup(&Name::new().label("aaaa").label("isi").label("edu"), RecordType::AAAA, false, SupportedAlgorithms::new()).first().cloned().unwrap();
  assert_eq!(&Name::new().label("aaaa").label("isi").label("edu"), aaaa_record.get_name());
  if let RData::AAAA(ref address) = *aaaa_record.get_rdata() {
    assert_eq!(&Ipv6Addr::from_str("4321:0:1:2:3:4:567:89ab").unwrap(), address);
  } else {
    panic!("Not a AAAA record!!!") // valid panic, test code
  }

  // SHORT
  let short_record: &Record = authority.lookup(&Name::new().label("short").label("isi").label("edu"), RecordType::A, false, SupportedAlgorithms::new()).first().cloned().unwrap();
  assert_eq!(&Name::new().label("short").label("isi").label("edu"), short_record.get_name());
  assert_eq!(70, short_record.get_ttl());
  if let RData::A(ref address) = *short_record.get_rdata() {
    assert_eq!(&Ipv4Addr::new(26u8,3u8,0u8,104u8), address);
  } else {
    panic!("Not an A record!!!") // valid panic, test code
  }

  // TXT
  let mut txt_records: Vec<&Record> = authority.lookup(&Name::new().label("a").label("isi").label("edu"), RecordType::TXT, false, SupportedAlgorithms::new());
  let compare = vec![
    vec!["I".to_string(), "am".to_string(), "a".to_string(), "txt".to_string(), "record".to_string()],
    vec!["I".to_string(), "am".to_string(), "another".to_string(), "txt".to_string(), "record".to_string()],
    vec!["key=val".to_string()],
    vec!["I am a different".to_string(), "txt record".to_string()],
    ];

  txt_records.sort();

  println!("compare: {:?}", compare);
  println!("txt_records: {:?}", txt_records);

  let compare = txt_records.iter().zip(compare);


  for (record, ref vector) in compare {
    if let RData::TXT(ref rdata) = *record.get_rdata() {
      assert_eq!(vector as &[String], rdata.get_txt_data());
    } else {
      panic!("Not a TXT record!!!") // valid panic, test code
    }
  }

  // PTR
  let ptr_record: &Record = authority.lookup(&Name::new().label("103").label("0").label("3").label("26").label("in-addr").label("arpa"), RecordType::PTR, false, SupportedAlgorithms::new()).first().cloned().unwrap();
  if let RData::PTR( ref ptrdname ) = *ptr_record.get_rdata() {
    assert_eq!(&Name::new().label("a").label("isi").label("edu"), ptrdname);
  } else {
    panic!("Not a PTR record!!!") // valid panic, test code
  }

  // SRV
  let srv_record: &Record = authority.lookup(&Name::new().label("_ldap").label("_tcp").label("service").label("isi").label("edu"), RecordType::SRV, false, SupportedAlgorithms::new()).first().cloned().unwrap();
  if let RData::SRV(ref rdata) = *srv_record.get_rdata() {
    assert_eq!(rdata.get_priority(), 1);
    assert_eq!(rdata.get_weight(), 2);
    assert_eq!(rdata.get_port(), 3);
    assert_eq!(rdata.get_target(), &Name::new().label("short").label("isi").label("edu"));
  } else {
    panic!("Not an SRV record!!!") // valid panic, test code
  }
}
