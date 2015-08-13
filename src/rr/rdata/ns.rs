use super::super::record_data::RData;
use super::super::domain::Name;

// 3.3.11. NS RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   NSDNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// NSDNAME         A <domain-name> which specifies a host which should be
//                 authoritative for the specified class and domain.
//
// NS records cause both the usual additional section processing to locate
// a type A record, and, when used in a referral, a special search of the
// zone in which they reside for glue information.
//
// The NS RR states that the named host should be expected to have a zone
// starting at owner name of the specified class.  Note that the class may
// not indicate the protocol family which should be used to communicate
// with the host, although it is typically a strong hint.  For example,
// hosts which are name servers for either Internet (IN) or Hesiod (HS)
// class information are normally queried using IN class protocols.
//
// NS { nsdname: Name },
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::NS{ nsdname: Name::parse(data).unwrap() }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0];
  data.reverse();
  if let RData::NS { nsdname } = parse(&mut data) {
    let expect = vec!["www","example","com"];
    assert_eq!(nsdname[0], expect[0]);
    assert_eq!(nsdname[1], expect[1]);
    assert_eq!(nsdname[2], expect[2]);
  } else {
    assert!(false);
  }
}
