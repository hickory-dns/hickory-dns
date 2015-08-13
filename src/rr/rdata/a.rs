use std::net::Ipv4Addr;
use std::str::FromStr;

use super::super::record_data::RData;

// 3.4. Internet specific RRs
//
// 3.4.1. A RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ADDRESS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// ADDRESS         A 32 bit Internet address.
//
// Hosts that have multiple Internet addresses will have multiple A
// records.
//
// A records cause no additional section processing.  The RDATA section of
// an A line in a master file is an Internet address expressed as four
// decimal numbers separated by dots without any imbedded spaces (e.g.,
// "10.2.0.52" or "192.0.5.6").
//
// A { address: Ipv4Addr }
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::A{ address: Ipv4Addr::new(data.pop().unwrap(), data.pop().unwrap(), data.pop().unwrap(), data.pop().unwrap()) }
}

#[test]
fn test_parse() {
  use std::net::Ipv4Addr;

  let data: Vec<(Vec<u8>, Ipv4Addr)> = vec![
    (vec![0,0,0,0], Ipv4Addr::from_str("0.0.0.0").unwrap()), // base case
    (vec![1,0,0,0], Ipv4Addr::from_str("1.0.0.0").unwrap()),
    (vec![0,1,0,0], Ipv4Addr::from_str("0.1.0.0").unwrap()),
    (vec![0,0,1,0], Ipv4Addr::from_str("0.0.1.0").unwrap()),
    (vec![0,0,0,1], Ipv4Addr::from_str("0.0.0.1").unwrap()),
    (vec![127,0,0,1], Ipv4Addr::from_str("127.0.0.1").unwrap()),
    (vec![192,168,64,32], Ipv4Addr::from_str("192.168.64.32").unwrap()),
  ];

  let mut test_num = 0;
  for (mut binary, expect) in data {
    test_num += 1;
    println!("test: {}", test_num);
    binary.reverse();
    if let RData::A{address} = parse(&mut binary) {
      assert_eq!(address, expect);
    } else {
      assert!(false);
    }
  }
}
