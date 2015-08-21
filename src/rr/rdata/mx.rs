use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;
use ::rr::domain::Name;

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
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::MX { preference: try!(decoder.read_u16()), exchange: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, mx: &RData) -> EncodeResult {
  if let RData::MX { ref preference, ref exchange } = *mx {
    try!(encoder.emit_u16(*preference));
    try!(exchange.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type here {:?}", mx);
  }
}

// #[test] is performed at the record_data module, the inner name in domain::Name
