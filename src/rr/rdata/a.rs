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
// A { address: u32 }
pub fn parse(data: &mut Vec<u8>) -> RData {
  unimplemented!()
}
