use super::super::record_data::RData;

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
  unimplemented!()
}
