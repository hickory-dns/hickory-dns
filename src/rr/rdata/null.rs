use super::super::record_data::RData;

// 3.3.10. NULL RDATA format (EXPERIMENTAL)
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                  <anything>                   /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// Anything at all may be in the RDATA field so long as it is 65535 octets
// or less.
//
// NULL records cause no additional section processing.  NULL RRs are not
// allowed in master files.  NULLs are used as placeholders in some
// experimental extensions of the DNS.
//
// NULL { anything: Vec<u8> },
pub fn parse(data: &mut Vec<u8>) -> RData {
  unimplemented!()
}

pub fn write_to(nil: &RData, buf: &mut Vec<u8>) {
  if let RData::NULL{ref anything} = *nil {
    for b in anything {
      buf.push(*b);
    }
  } else {
    panic!("wrong type here {:?}", nil);
  }
}
