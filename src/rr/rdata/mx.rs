use super::super::record_data::RData;
use super::super::util;
use super::super::domain::Name;

// 3.3.9. MX RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                  PREFERENCE                   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   EXCHANGE                    /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// PREFERENCE      A 16 bit integer which specifies the preference given to
//                 this RR among others at the same owner.  Lower values
//                 are preferred.
//
// EXCHANGE        A <domain-name> which specifies a host willing to act as
//                 a mail exchange for the owner name.
//
// MX records cause type A additional section processing for the host
// specified by EXCHANGE.  The use of MX RRs is explained in detail in
// [RFC-974].
//
// MX { preference: u16, exchange: Name },
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::MX { preference: util::parse_u16(data), exchange: Name::parse(data).unwrap() }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![1,0,1,b'n',0];
  data.reverse();

  if let RData::MX{ preference, exchange } = parse(&mut data) {
    assert_eq!(preference, 256);
    assert_eq!(exchange[0], "n".to_string());
  } else {
    assert!(false);
  }
}
