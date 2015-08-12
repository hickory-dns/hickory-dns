use super::super::record_data::RData;

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
  unimplemented!()
}
