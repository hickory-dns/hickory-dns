//use std::collections::HashMap;
//use std::error::Error;
use std::string::FromUtf8Error;
use std::io::Read;
use std::iter;
use std::slice::{IterMut,Iter};

use super::record_data::RData;
use super::record_type::RecordType;
use super::dns_class::DNSClass;
use super::domain;

pub struct Record {
  name_labels: domain::Name,
  rr_type: RecordType,
  dns_class: DNSClass,
  ttl: i32,
  rdata: RData,
}

impl Record {

  /// parse a resource record line example:
  pub fn parse(record_bytes: Vec<u8>) -> Result<Record, FromUtf8Error> {
    // TODO: it would be better to pass iter to all of these methods, but String::from_utf8 makes that complicated
    let mut data: Vec<u8> = record_bytes;

    // NAME            an owner name, i.e., the name of the node to which this
    //                 resource record pertains.
    let name_labels: domain::Name = try!(domain::Name::parse(&mut data));

    // TYPE            two octets containing one of the RR TYPE codes.
    let record_type: RecordType = RecordType::from(Self::parse_u16(&mut data));

    // CLASS           two octets containing one of the RR CLASS codes.
    let class: DNSClass = DNSClass::from(Self::parse_u16(&mut data));

    // TTL             a 32 bit signed integer that specifies the time interval
    //                that the resource record may be cached before the source
    //                of the information should again be consulted.  Zero
    //                values are interpreted to mean that the RR can only be
    //                used for the transaction in progress, and should not be
    //                cached.  For example, SOA records are always distributed
    //                with a zero TTL to prohibit caching.  Zero values can
    //                also be used for extremely volatile data.
    let ttl: i32 = Self::parse_i32(&mut data);

    // RDLENGTH        an unsigned 16 bit integer that specifies the length in
    //                octets of the RDATA field.
    let rd_length: u16 = Self::parse_u16(&mut data);

    // RDATA           a variable length string of octets that describes the
    //                resource.  The format of this information varies
    //                according to the TYPE and CLASS of the resource record.
    let rdata = RData::parse(&mut data, &record_type, rd_length);

    Ok(Record{ name_labels: name_labels, rr_type: record_type, dns_class: class, ttl: ttl, rdata: rdata })
  }

  /// parses the next 2 bytes into u16. This performs a byte-by-byte manipulation, there
  ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
  fn parse_u16(data: &mut Vec<u8>) -> u16 {
    // TODO use Drain once it stabalizes...
    let b1: u8 = data.remove(0);
    let b2: u8 = data.remove(0);

    // translate from network byte order, i.e. big endian
    ((b1 as u16) << 8) + (b2 as u16)
  }

  /// parses the next four bytes into i32. This performs a byte-by-byte manipulation, there
  ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
  fn parse_i32(data: &mut Vec<u8>) -> i32 {
    // TODO use Drain once it stabalizes...
    let b1: u8 = data.remove(0);
    let b2: u8 = data.remove(0);
    let b3: u8 = data.remove(0);
    let b4: u8 = data.remove(0);

    // translate from network byte order, i.e. big endian
    ((b1 as i32) << 24) + ((b2 as i32) << 16) + ((b3 as i32) << 8) + (b4 as i32)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_u16() {
    let data: Vec<(Vec<u8>, u16)> = vec![
      (vec![0x00,0x00], 0),
      (vec![0x00,0x01], 1),
      (vec![0x01,0x00], 256),
      (vec![0xFF,0xFF], u16::max_value()),
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      assert_eq!(Record::parse_u16(&mut binary), expect);
    }
  }

  #[test]
  fn parse_i32() {
    let data: Vec<(Vec<u8>, i32)> = vec![
      (vec![0x00,0x00,0x00,0x00], 0),
      (vec![0x00,0x00,0x00,0x01], 1),
      (vec![0x00,0x00,0x01,0x00], 256),
      (vec![0x00,0x01,0x00,0x00], 256*256),
      (vec![0x01,0x00,0x00,0x00], 256*256*256),
      (vec![0xFF,0xFF,0xFF,0xFF], -1),
      (vec![0x80,0x00,0x00,0x00], i32::min_value()),
      (vec![0x7F,0xFF,0xFF,0xFF], i32::max_value()),
    ];

    let mut test_num = 0;
    for (mut binary, expect) in data {
      test_num += 1;
      println!("test: {}", test_num);
      assert_eq!(Record::parse_i32(&mut binary), expect);
    }
  }
}
