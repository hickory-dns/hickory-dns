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
use super::util;

/*
 * RFC 1035        Domain Implementation and Specification    November 1987
 *
 * 4.1.3. Resource record format
 *
 * The answer, authority, and additional sections all share the same
 * format: a variable number of resource records, where the number of
 * records is specified in the corresponding count field in the header.
 * Each resource record has the following format:
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                                               |
 *     /                                               /
 *     /                      NAME                     /
 *     |                                               |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      TYPE                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     CLASS                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      TTL                      |
 *     |                                               |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                   RDLENGTH                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *     /                     RDATA                     /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * NAME            a domain name to which this resource record pertains.
 *
 * TYPE            two octets containing one of the RR type codes.  This
 *                 field specifies the meaning of the data in the RDATA
 *                 field.
 *
 * CLASS           two octets which specify the class of the data in the
 *                 RDATA field.
 *
 * TTL             a 32 bit unsigned integer that specifies the time
 *                 interval (in seconds) that the resource record may be
 *                 cached before it should be discarded.  Zero values are
 *                 interpreted to mean that the RR can only be used for the
 *                 transaction in progress, and should not be cached.
 *
 * RDLENGTH        an unsigned 16 bit integer that specifies the length in
 *                 octets of the RDATA field.
 *
 * RDATA           a variable length string of octets that describes the
 *                 resource.  The format of this information varies
 *                 according to the TYPE and CLASS of the resource record.
 *                 For example, the if the TYPE is A and the CLASS is IN,
 *                 the RDATA field is a 4 octet ARPA Internet address.
 */
pub struct Record {
  name_labels: domain::Name,
  rr_type: RecordType,
  dns_class: DNSClass,
  ttl: i32,
  rdata: RData,
}

impl Record {

  /// parse a resource record line example:
  ///  WARNING: the record_bytes is 100% consumed and destroyed in this parsing process
  pub fn parse(data: &mut Vec<u8>) -> Result<Record, FromUtf8Error> {
    // NAME            an owner name, i.e., the name of the node to which this
    //                 resource record pertains.
    let name_labels: domain::Name = domain::Name::parse(data);

    // TYPE            two octets containing one of the RR TYPE codes.
    let record_type: RecordType = RecordType::parse(data);

    // CLASS           two octets containing one of the RR CLASS codes.
    let class: DNSClass = DNSClass::parse(data);

    // TTL             a 32 bit signed integer that specifies the time interval
    //                that the resource record may be cached before the source
    //                of the information should again be consulted.  Zero
    //                values are interpreted to mean that the RR can only be
    //                used for the transaction in progress, and should not be
    //                cached.  For example, SOA records are always distributed
    //                with a zero TTL to prohibit caching.  Zero values can
    //                also be used for extremely volatile data.
    let ttl: i32 = util::parse_i32(data);

    // RDLENGTH        an unsigned 16 bit integer that specifies the length in
    //                octets of the RDATA field.
    let rd_length: u16 = util::parse_u16(data);

    // RDATA           a variable length string of octets that describes the
    //                resource.  The format of this information varies
    //                according to the TYPE and CLASS of the resource record.
    let rdata = RData::parse(data, &record_type, rd_length);

    Ok(Record{ name_labels: name_labels, rr_type: record_type, dns_class: class, ttl: ttl, rdata: rdata })
  }

  pub fn write_to(&self, buf: &mut Vec<u8>) {
    self.name_labels.write_to(buf);
    self.rr_type.write_to(buf);
    self.dns_class.write_to(buf);
    util::write_i32_to(buf, self.ttl);

    // TODO: gah... need to write rdata before we know the size of rdata...
    let mut tmp_buf: Vec<u8> = Vec::with_capacity(255); // making random space
    self.rdata.write_to(&mut tmp_buf);

    assert!(tmp_buf.len() <= u16::max_value() as usize);

    util::write_u16_to(buf, tmp_buf.len() as u16);
    buf.reserve(tmp_buf.len());

    tmp_buf.reverse();
    while let Some(byte) = tmp_buf.pop() {
      buf.push(byte);
    }
  }
}
