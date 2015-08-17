use std::net::Ipv6Addr;

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

pub fn write_to(aaaa: &RData, buf: &mut Vec<u8>) {
  if let RData::AAAA { address } = *aaaa {
    let segments = address.segments();

    util::write_u16_to(buf, segments[0]);
    util::write_u16_to(buf, segments[1]);
    util::write_u16_to(buf, segments[2]);
    util::write_u16_to(buf, segments[3]);
    util::write_u16_to(buf, segments[4]);
    util::write_u16_to(buf, segments[5]);
    util::write_u16_to(buf, segments[6]);
    util::write_u16_to(buf, segments[7]);
  } else {
    panic!("wrong type here {:?}", aaaa)
  }
}


#[cfg(test)]
mod tests {
  use std::net::Ipv6Addr;
  use std::str::FromStr;

  use super::*;
  use super::super::super::record_data::RData;
  use super::super::super::util::tests::{test_parse_data_set, test_write_data_set_to};

  fn get_data() -> Vec<(RData, Vec<u8>)> {
    vec![
    (RData::AAAA{ address: Ipv6Addr::from_str("::").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]), // base case
    (RData::AAAA{ address: Ipv6Addr::from_str("1::").unwrap()}, vec![0,1,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("0:1::").unwrap()}, vec![0,0,0,1,0,0,0,0, 0,0,0,0,0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("0:0:1::").unwrap()}, vec![0,0,0,0,0,1,0,0, 0,0,0,0,0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("0:0:0:1::").unwrap()}, vec![0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::1:0:0:0").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,1,0,0,0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::1:0:0").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,1,0,0,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::1:0").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,1,0,0]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::1").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1]),
    (RData::AAAA{ address: Ipv6Addr::from_str("::127.0.0.1").unwrap()}, vec![0,0,0,0,0,0,0,0, 0,0,0,0,127,0,0,1]),
    (RData::AAAA{ address: Ipv6Addr::from_str("FF00::192.168.64.32").unwrap()}, vec![255,0,0,0,0,0,0,0, 0,0,0,0,192,168,64,32]),
    ]
  }

  #[test]
  fn test_parse() {
    test_parse_data_set(get_data(), |b| parse(b));
  }

  #[test]
  fn test_write_to() {
    test_write_data_set_to(get_data(), |b,d| write_to(&d,b));
  }
}
