use super::super::record_data::RData;
use super::super::util;

// 3.3.2. HINFO RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                      CPU                      /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                       OS                      /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// CPU             A <character-string> which specifies the CPU type.
//
// OS              A <character-string> which specifies the operating
//                 system type.
//
// Standard values for CPU and OS can be found in [RFC-1010].
//
// HINFO records are used to acquire general information about a host.  The
// main use is for protocols such as FTP that can use special procedures
// when talking between machines or operating systems of the same type.
//
// HINFO { cpu: String, os: String},
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::HINFO { cpu: util::parse_character_data(data).unwrap(), os: util::parse_character_data(data).unwrap() }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![6,b'x',b'8',b'6',b'_',b'6',b'4',5,b'l',b'i',b'n',b'u',b'x'];
  data.reverse();

  if let RData::HINFO{cpu, os} = parse(&mut data) {
    assert_eq!(cpu, "x86_64".to_string());
    assert_eq!(os, "linux".to_string());
  } else {
    assert!(false);
  }
}
