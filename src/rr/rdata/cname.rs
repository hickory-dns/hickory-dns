use super::super::record_data::RData;
use super::super::domain::Name;

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
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::CNAME{ cname: Name::parse(data) }
}

pub fn write_to(cname_data: &RData, buf: &mut Vec<u8>) {
  if let RData::CNAME { ref cname } = *cname_data {
    cname.write_to(buf);
  } else {
    panic!("wrong type: {:?}", cname_data)
  }
}

// #[test] is performed at the record_data module, the inner name in domain::Name
