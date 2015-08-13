use super::super::record_data::RData;
use super::super::domain::Name;

// 3.3.12. PTR RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   PTRDNAME                    /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// PTRDNAME        A <domain-name> which points to some location in the
//                 domain name space.
//
// PTR records cause no additional section processing.  These RRs are used
// in special domains to point to some other location in the domain space.
// These records are simple data, and don't imply any special processing
// similar to that performed by CNAME, which identifies aliases.  See the
// description of the IN-ADDR.ARPA domain for an example.
//
// PTR { ptrdname: Name },
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::PTR{ ptrdname: Name::parse(data).unwrap() }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0];
  data.reverse();
  if let RData::PTR { ptrdname } = parse(&mut data) {
    let expect = vec!["www","example","com"];
    assert_eq!(ptrdname[0], expect[0]);
    assert_eq!(ptrdname[1], expect[1]);
    assert_eq!(ptrdname[2], expect[2]);
  } else {
    assert!(false);
  }
}
