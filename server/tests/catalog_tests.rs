extern crate trust_dns;
extern crate trust_dns_server;

use std::net::*;
use std::collections::*;

use trust_dns::op::*;
use trust_dns::rr::*;
use trust_dns::rr::rdata::*;

use trust_dns_server::authority::*;
use trust_dns_server::authority::authority::create_example;

pub fn create_test() -> Authority {
  let origin: Name = Name::parse("test.com.", None).unwrap();
  let mut records: Authority = Authority::new(origin.clone(), BTreeMap::new(), ZoneType::Master, false);
  records.upsert(Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone(), 0);

  records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(), 0);
  records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone(), 0);

  records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(94,184,216,34))).clone(), 0);
  records.upsert(Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(), 0);

  let www_name: Name = Name::parse("www.test.com.", None).unwrap();
  records.upsert(Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(94,184,216,34))).clone(), 0);
  records.upsert(Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(), 0);

  records
}

#[test]
fn test_catalog_lookup() {
  let example = create_example();
  let test = create_test();
  let origin = example.get_origin().clone();
  let test_origin = test.get_origin().clone();

  let mut catalog: Catalog = Catalog::new();
  catalog.upsert(origin.clone(), example);
  catalog.upsert(test_origin.clone(), test);

  let mut question: Message = Message::new();

  let mut query: Query = Query::new();
  query.name(origin.clone());

  question.add_query(query);

  let result: Message = catalog.lookup(&question);

  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_message_type(), MessageType::Response);

  let answers: &[Record] = result.get_answers();

  assert!(!answers.is_empty());
  assert_eq!(answers.first().unwrap().get_rr_type(), RecordType::A);
  assert_eq!(answers.first().unwrap().get_rdata(), &RData::A(Ipv4Addr::new(93,184,216,34)));

  let mut ns: Vec<Record> = result.get_name_servers().to_vec();
  ns.sort();

  assert_eq!(ns.len(), 2);
  assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::NS);
  assert_eq!(ns.first().unwrap().get_rdata(), &RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) );
  assert_eq!(ns.last().unwrap().get_rr_type(), RecordType::NS);
  assert_eq!(ns.last().unwrap().get_rdata(), &RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) );

  // other zone
  let mut query: Query = Query::new();
  query.name(test_origin.clone());

  question.add_query(query);

  let result: Message = catalog.lookup(&question);

  assert_eq!(result.get_response_code(), ResponseCode::NoError);
  assert_eq!(result.get_message_type(), MessageType::Response);

  let answers: &[Record] = result.get_answers();

  assert!(!answers.is_empty());
  assert_eq!(answers.first().unwrap().get_rr_type(), RecordType::A);
  assert_eq!(answers.first().unwrap().get_rdata(), &RData::A(Ipv4Addr::new(93,184,216,34)));
}

#[test]
fn test_catalog_nx_soa() {
  let example = create_example();
  let origin = example.get_origin().clone();

  let mut catalog: Catalog = Catalog::new();
  catalog.upsert(origin.clone(), example);

  let mut question: Message = Message::new();

  let mut query: Query = Query::new();
  query.name(Name::parse("nx.example.com.", None).unwrap());

  question.add_query(query);

  let result: Message = catalog.lookup(&question);

  assert_eq!(result.get_response_code(), ResponseCode::NXDomain);
  assert_eq!(result.get_message_type(), MessageType::Response);

  let ns: &[Record] = result.get_name_servers();

  assert_eq!(ns.len(), 1);
  assert_eq!(ns.first().unwrap().get_rr_type(), RecordType::SOA);
  assert_eq!(ns.first().unwrap().get_rdata(), &RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 )));
}

#[test]
fn test_axfr() {
  let test = create_test();
  let origin = test.get_origin().clone();
  let soa = Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone();

  let mut catalog: Catalog = Catalog::new();
  catalog.upsert(origin.clone(), test);

  let mut query: Query = Query::new();
  query.name(origin.clone());
  query.query_type(RecordType::AXFR);

  let mut question: Message = Message::new();
  question.add_query(query);

  let result: Message = catalog.lookup(&question);
  let mut answers: Vec<Record> = result.get_answers().to_vec();

  assert_eq!(answers.first().unwrap(), &soa);
  assert_eq!(answers.last().unwrap(), &soa);

  answers.sort();

  let www_name: Name = Name::parse("www.test.com.", None).unwrap();
  let mut expected_set = vec![
  Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone(),
  Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(),
  Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone(),
  Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(94,184,216,34))).clone(),
  Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(),
  Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::A).dns_class(DNSClass::IN).rdata(RData::A(Ipv4Addr::new(94,184,216,34))).clone(),
  Record::new().name(www_name.clone()).ttl(86400).rr_type(RecordType::AAAA).dns_class(DNSClass::IN).rdata(RData::AAAA(Ipv6Addr::new(0x2606,0x2800,0x220,0x1,0x248,0x1893,0x25c8,0x1946))).clone(),
  Record::new().name(origin.clone()).ttl(3600).rr_type(RecordType::SOA).dns_class(DNSClass::IN).rdata(RData::SOA(SOA::new(Name::parse("sns.dns.icann.org.", None).unwrap(), Name::parse("noc.dns.icann.org.", None).unwrap(), 2015082403, 7200, 3600, 1209600, 3600 ))).clone(),
  ];

  expected_set.sort();

  assert_eq!(expected_set, answers);
}
