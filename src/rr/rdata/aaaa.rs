use std::net::Ipv6Addr;
use std::str::FromStr;

use super::super::record_data::RData;
use super::super::util;
//-- RFC 1886 -- IPv6 DNS Extensions              December 1995

// 2.2 AAAA data format
//
//    A 128 bit IPv6 address is encoded in the data portion of an AAAA
//    resource record in network byte order (high-order byte first).
//
// AAAA { address: Ipv6Addr }
pub fn parse(data: &mut Vec<u8>) -> RData {
  let a: u16 = util::parse_u16(data);
  let b: u16 = util::parse_u16(data);
  let c: u16 = util::parse_u16(data);
  let d: u16 = util::parse_u16(data);
  let e: u16 = util::parse_u16(data);
  let f: u16 = util::parse_u16(data);
  let g: u16 = util::parse_u16(data);
  let h: u16 = util::parse_u16(data);

  RData::AAAA{ address: Ipv6Addr::new(a,b,c,d,e,f,g,h)}
}

#[test]
fn test_parse() {
  use std::net::Ipv6Addr;

  let data: Vec<(Vec<u8>, Ipv6Addr)> = vec![
    (vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0], Ipv6Addr::from_str("::").unwrap()), // base case
    (vec![0,1,0,0,0,0,0,0, 0,0,0,0,0,0,0,0], Ipv6Addr::from_str("1::").unwrap()),
    (vec![0,0,0,1,0,0,0,0, 0,0,0,0,0,0,0,0], Ipv6Addr::from_str("0:1::").unwrap()),
    (vec![0,0,0,0,0,1,0,0, 0,0,0,0,0,0,0,0], Ipv6Addr::from_str("0:0:1::").unwrap()),
    (vec![0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0], Ipv6Addr::from_str("0:0:0:1::").unwrap()),
    (vec![0,0,0,0,0,0,0,0, 0,1,0,0,0,0,0,0], Ipv6Addr::from_str("::1:0:0:0").unwrap()),
    (vec![0,0,0,0,0,0,0,0, 0,0,0,1,0,0,0,0], Ipv6Addr::from_str("::1:0:0").unwrap()),
    (vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,1,0,0], Ipv6Addr::from_str("::1:0").unwrap()),
    (vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1], Ipv6Addr::from_str("::1").unwrap()),
    (vec![0,0,0,0,0,0,0,0, 0,0,0,0,127,0,0,1], Ipv6Addr::from_str("::127.0.0.1").unwrap()),
    (vec![255,0,0,0,0,0,0,0, 0,0,0,0,192,168,64,32], Ipv6Addr::from_str("FF00::192.168.64.32").unwrap()),
  ];

  let mut test_num = 0;
  for (mut binary, expect) in data {
    test_num += 1;
    println!("test: {}", test_num);
    binary.reverse();
    if let RData::AAAA{address} = parse(&mut binary) {
      assert_eq!(address, expect);
    } else {
      panic!();
    }
  }
}
