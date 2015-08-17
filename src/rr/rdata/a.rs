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

pub fn write_to(a: &RData, buf: &mut Vec<u8>) {
  if let RData::A { address } = *a {
    let segments = address.octets();

    buf.push(segments[0]);
    buf.push(segments[1]);
    buf.push(segments[2]);
    buf.push(segments[3]);
  } else {
    panic!("wrong type here {:?}", a)
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;
  use std::str::FromStr;

  use super::*;
  use super::super::super::record_data::RData;
  use super::super::super::util::tests::{test_parse_data_set, test_write_data_set_to};

  fn get_data() -> Vec<(RData, Vec<u8>)> {
    vec![
    (RData::A{ address: Ipv4Addr::from_str("0.0.0.0").unwrap()}, vec![0,0,0,0]), // base case
    (RData::A{ address: Ipv4Addr::from_str("1.0.0.0").unwrap()}, vec![1,0,0,0]),
    (RData::A{ address: Ipv4Addr::from_str("0.1.0.0").unwrap()}, vec![0,1,0,0]),
    (RData::A{ address: Ipv4Addr::from_str("0.0.1.0").unwrap()}, vec![0,0,1,0]),
    (RData::A{ address: Ipv4Addr::from_str("0.0.0.1").unwrap()}, vec![0,0,0,1]),
    (RData::A{ address: Ipv4Addr::from_str("127.0.0.1").unwrap()}, vec![127,0,0,1]),
    (RData::A{ address: Ipv4Addr::from_str("192.168.64.32").unwrap()}, vec![192,168,64,32]),
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
