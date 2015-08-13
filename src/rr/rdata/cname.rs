use super::super::record_data::RData;
use super::super::domain::Name;

// 3.3.1. CNAME RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                     CNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// CNAME           A <domain-name> which specifies the canonical or primary
//                 name for the owner.  The owner name is an alias.
//
// CNAME RRs cause no additional section processing, but name servers may
// choose to restart the query at the canonical name in certain cases.  See
// the description of name server logic in [RFC-1034] for details.
//
// CNAME { cname: Name },
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::CNAME{ cname: Name::parse(data).unwrap() }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0];
  data.reverse();
  if let RData::CNAME { cname } = parse(&mut data) {
    let expect = vec!["www","example","com"];
    assert_eq!(cname[0], expect[0]);
    assert_eq!(cname[1], expect[1]);
    assert_eq!(cname[2], expect[2]);
  } else {
    assert!(false);
  }

}
