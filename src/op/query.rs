use super::super::rr::domain::Name;
use super::super::rr::record_type::RecordType;
use super::super::rr::dns_class::DNSClass;

/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * 4.1.2. Question section format
 *
 * The question section is used to carry the "question" in most queries,
 * i.e., the parameters that define what is being asked.  The section
 * contains QDCOUNT (usually 1) entries, each of the following format:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                                               |
 *     /                     QNAME                     /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     QTYPE                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     QCLASS                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * QNAME           a domain name represented as a sequence of labels, where
 *                 each label consists of a length octet followed by that
 *                 number of octets.  The domain name terminates with the
 *                 zero length octet for the null label of the root.  Note
 *                 that this field may be an odd number of octets; no
 *                 padding is used.
 *
 * QTYPE           a two octet code which specifies the type of the query.
 *                 The values for this field include all codes valid for a
 *                 TYPE field, together with some more general codes which
 *                 can match more than one type of RR.
 *
 * QCLASS          a two octet code that specifies the class of the query.
 *                 For example, the QCLASS field is IN for the Internet.
 */
#[derive(PartialEq, Debug)]
pub struct Query {
  name: Name, query_type: RecordType, query_class: DNSClass
}

impl Query {
  /// return a default query with an empty name and A, IN for the query_type and query_class
  pub fn new() -> Self {
    Query { name: Name::new(), query_type: RecordType::A, query_class: DNSClass::IN }
  }

  /// replaces name with the new name
  pub fn name(&mut self, name: Name) -> &mut Self { self.name = name; self }
  pub fn query_type(&mut self, query_type: RecordType) -> &mut Self { self.query_type = query_type; self }
  pub fn query_class(&mut self, query_class: DNSClass) -> &mut Self { self.query_class = query_class; self }

  // TODO: these functions certainly seem like they could just be rustc::encodable
  pub fn parse(data: &mut Vec<u8>) -> Self {
    let name = Name::parse(data);
    let query_type = RecordType::parse(data);
    let query_class = DNSClass::parse(data);

    Query { name: name, query_type: query_type, query_class: query_class}
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    self.name.write_to(buf);
    self.query_type.write_to(buf);
    self.query_class.write_to(buf);
  }
}

#[test]
fn test_parse_and_write() {
  let expect = Query { name: Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
                       query_type: RecordType::AAAA, query_class: DNSClass::IN };

  let mut written = Vec::new();
  expect.write_to(&mut written);
  written.reverse(); // flip it around to read in...

  let got = Query::parse(&mut written);
  assert_eq!(got, expect);
}
