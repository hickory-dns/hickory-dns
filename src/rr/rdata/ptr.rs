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
  RData::PTR{ ptrdname: Name::parse(data) }
}

pub fn write_to(ptr: &RData, buf: &mut Vec<u8>) {
  if let RData::PTR { ref ptrdname } = *ptr {
    ptrdname.write_to(buf);
  } else {
    panic!()
  }
}
