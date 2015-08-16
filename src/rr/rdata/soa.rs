use super::super::record_data::RData;
use super::super::util;
use super::super::domain::Name;

// 3.3.13. SOA RDATA format
//
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                     MNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                     RNAME                     /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    SERIAL                     |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    REFRESH                    |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     RETRY                     |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    EXPIRE                     |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    MINIMUM                    |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// where:
//
// MNAME           The <domain-name> of the name server that was the
//                 original or primary source of data for this zone.
//
// RNAME           A <domain-name> which specifies the mailbox of the
//                 person responsible for this zone.
//
// SERIAL          The unsigned 32 bit version number of the original copy
//                 of the zone.  Zone transfers preserve this value.  This
//                 value wraps and should be compared using sequence space
//                 arithmetic.
//
// REFRESH         A 32 bit time interval before the zone should be
//                 refreshed.
//
// RETRY           A 32 bit time interval that should elapse before a
//                 failed refresh should be retried.
//
// EXPIRE          A 32 bit time value that specifies the upper limit on
//                 the time interval that can elapse before the zone is no
//                 longer authoritative.
//
// MINIMUM         The unsigned 32 bit minimum TTL field that should be
//                 exported with any RR from this zone.
//
// SOA records cause no additional section processing.
//
// All times are in units of seconds.
//
// Most of these fields are pertinent only for name server maintenance
// operations.  However, MINIMUM is used in all query operations that
// retrieve RRs from a zone.  Whenever a RR is sent in a response to a
// query, the TTL field is set to the maximum of the TTL field from the RR
// and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
// bound on the TTL field for all RRs in a zone.  Note that this use of
// MINIMUM should occur when the RRs are copied into the response and not
// when the zone is loaded from a master file or via a zone transfer.  The
// reason for this provison is to allow future dynamic update facilities to
// change the SOA RR with known semantics.
//
// SOA { mname: Name, rname: Name, serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32, },
pub fn parse(data: &mut Vec<u8>) -> RData {
  RData::SOA{
    mname:   Name::parse(data),
    rname:   Name::parse(data),
    serial:  util::parse_u32(data),
    refresh: util::parse_i32(data),
    retry:   util::parse_i32(data),
    expire:  util::parse_i32(data),
    minimum: util::parse_u32(data),
  }
}

#[test]
fn test_parse() {
  let mut data: Vec<u8> = vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0,
                               3,b'x',b'x',b'x',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0,
                               0xFF,0xFF,0xFF,0xFF,
                               0xFF,0xFF,0xFF,0xFF,
                               0xFF,0xFF,0xFF,0xFF,
                               0xFF,0xFF,0xFF,0xFF,
                               0xFF,0xFF,0xFF,0xFF];
  data.reverse();
  if let RData::SOA { mname, rname, serial, refresh, retry, expire, minimum } = parse(&mut data) {
    let expect1 = vec!["www","example","com"];
    let expect2 = vec!["xxx","example","com"];

    assert_eq!(mname[0], expect1[0]);
    assert_eq!(rname[0], expect2[0]);
    assert_eq!(serial,  u32::max_value());
    assert_eq!(refresh, -1 as i32);
    assert_eq!(retry,   -1 as i32);
    assert_eq!(expire,  -1 as i32);
    assert_eq!(minimum, u32::max_value());
  } else {
    panic!();
  }
}
