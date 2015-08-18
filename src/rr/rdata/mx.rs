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
  RData::MX { preference: util::parse_u16(data), exchange: Name::parse(data) }
}

pub fn write_to(mx: &RData, buf: &mut Vec<u8>) {
  if let RData::MX { ref preference, ref exchange } = *mx {
    util::write_u16_to(buf, *preference);
    exchange.write_to(buf);
  } else {
    panic!("wrong type here {:?}", mx);
  }
}

// #[test] is performed at the record_data module, the inner name in domain::Name
