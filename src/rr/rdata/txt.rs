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

#[test]
fn test_parse() {
  let mut data = vec![6,b'a',b'b',b'c',b'd',b'e',b'f',
                      3,b'g',b'h',b'i',
                      0,
                      1,b'j'];
  data.reverse();

  if let RData::TXT{ txt_data } = parse(&mut data, 14) {
    assert_eq!(txt_data[0], "abcdef".to_string());
    assert_eq!(txt_data[1], "ghi".to_string());
    assert_eq!(txt_data[2], "".to_string());
    assert_eq!(txt_data[3], "j".to_string());
  } else {
    panic!();
  }
}
