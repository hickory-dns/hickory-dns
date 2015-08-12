use super::super::record_data::RData;
//-- RFC 1886 -- IPv6 DNS Extensions              December 1995

// 2.2 AAAA data format
//
//    A 128 bit IPv6 address is encoded in the data portion of an AAAA
//    resource record in network byte order (high-order byte first).
//
// AAAA { high: u64, low: u64 }
pub fn parse(data: &mut Vec<u8>) -> RData {
  unimplemented!()
}
