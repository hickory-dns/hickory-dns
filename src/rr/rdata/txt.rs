use super::super::record_data::RData;

// 3.3.14. TXT RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   TXT-DATA                    /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// TXT-DATA        One or more <character-string>s.
//
// TXT RRs are used to hold descriptive text.  The semantics of the text
// depends on the domain where it is found.
//
// TXT { txt_data: Vec<String> }
pub fn parse(data: &mut Vec<u8>) -> RData {
  unimplemented!()
}
