use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;
use ::rr::domain::Name;

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
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::CNAME{ cname: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, cname_data: &RData) -> EncodeResult {
  if let RData::CNAME { ref cname } = *cname_data {
    try!(cname.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type: {:?}", cname_data)
  }
}

// #[test] is performed at the record_data module, the inner name in domain::Name
