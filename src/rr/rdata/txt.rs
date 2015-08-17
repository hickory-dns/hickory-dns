use std::string::FromUtf8Error;

use super::super::record_data::RData;
use super::super::util;

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
pub fn parse(data: &mut Vec<u8>, count: u16) -> RData {
  let data_len = data.len();
  let mut strings = Vec::with_capacity(1);

  while data_len - data.len() < count as usize {
    strings.push(util::parse_character_data(data));
  }
  RData::TXT{ txt_data: strings }
}

pub fn write_to(txt: &RData, buf: &mut Vec<u8>) {
  if let RData::TXT { ref txt_data } = *txt {
    for s in txt_data {
      util::write_character_data_to(buf, s);
    }
  } else {
    panic!()
  }
}
