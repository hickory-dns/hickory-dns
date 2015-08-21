use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;
use ::rr::domain::Name;

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
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  Ok(RData::PTR{ ptrdname: try!(Name::read(decoder)) })
}

pub fn emit(encoder: &mut BinEncoder, ptr: &RData) -> EncodeResult {
  if let RData::PTR { ref ptrdname } = *ptr {
    try!(ptrdname.emit(encoder));
    Ok(())
  } else {
    panic!("wrong type: {:?}", ptr)
  }
}
