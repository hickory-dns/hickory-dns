use std::net::Ipv4Addr;

use ::serialize::binary::*;
use ::error::*;
use super::record_data::RData;
use super::record_type::RecordType;
use super::dns_class::DNSClass;
use super::domain;

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
#[derive(PartialEq, Debug)]
pub struct Record {
  name_labels: domain::Name,
  rr_type: RecordType,
  dns_class: DNSClass,
  ttl: i32,
  rdata: RData,
}

impl Record {
  /**
   * Creates a not very useful empty record, use the setters to build a more useful object
   *  There are no optional elements in this object, defaults are an empty name, type A, class IN,
   *  ttl of 0 and the 0.0.0.0 ip address.
   */
  pub fn new() -> Record {
    Record {
      name_labels: domain::Name::new(),
      rr_type: RecordType::A,
      dns_class: DNSClass::IN,
      ttl: 0,
      rdata: RData::A { address: Ipv4Addr::new(0,0,0,0) }
    }
  }

  pub fn add_name(&mut self, label: String) -> &mut Self { self.name_labels.add_label(label); self }
  pub fn rr_type(&mut self, rr_type: RecordType) -> &mut Self { self.rr_type = rr_type; self }
  pub fn dns_class(&mut self, dns_class: DNSClass) -> &mut Self { self.dns_class = dns_class; self }
  pub fn ttl(&mut self, ttl: i32) -> &mut Self { self.ttl = ttl; self }
  pub fn rdata(&mut self, rdata: RData) -> &mut Self { self.rdata = rdata; self }

  pub fn get_name(&self) -> &domain::Name { &self.name_labels }
  pub fn get_rr_type(&self) -> RecordType { self.rr_type }
  pub fn get_dns_class(&self) -> DNSClass { self.dns_class }
  pub fn get_ttl(&self) -> i32 { self.ttl }
  pub fn get_rdata(&self) -> &RData { &self.rdata }
}

impl BinSerializable for Record {
  /// parse a resource record line example:
  ///  WARNING: the record_bytes is 100% consumed and destroyed in this parsing process
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Record> {
    // NAME            an owner name, i.e., the name of the node to which this
    //                 resource record pertains.
    let name_labels: domain::Name = try!(domain::Name::read(decoder));

    // TYPE            two octets containing one of the RR TYPE codes.
    let record_type: RecordType = try!(RecordType::read(decoder));
    decoder.set_record_type(record_type);

    // CLASS           two octets containing one of the RR CLASS codes.
    let class: DNSClass = try!(DNSClass::read(decoder));

    // TTL             a 32 bit signed integer that specifies the time interval
    //                that the resource record may be cached before the source
    //                of the information should again be consulted.  Zero
    //                values are interpreted to mean that the RR can only be
    //                used for the transaction in progress, and should not be
    //                cached.  For example, SOA records are always distributed
    //                with a zero TTL to prohibit caching.  Zero values can
    //                also be used for extremely volatile data.
    let ttl: i32 = try!(decoder.read_i32());

    // RDLENGTH        an unsigned 16 bit integer that specifies the length in
    //                octets of the RDATA field.
    let rd_length: u16 = try!(decoder.read_u16());
    decoder.set_rdata_length(rd_length);

    // RDATA           a variable length string of octets that describes the
    //                resource.  The format of this information varies
    //                according to the TYPE and CLASS of the resource record.
    let rdata = try!(RData::read(decoder));

    Ok(Record{ name_labels: name_labels, rr_type: record_type, dns_class: class, ttl: ttl, rdata: rdata })
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    try!(self.name_labels.emit(encoder));
    try!(self.rr_type.emit(encoder));
    try!(self.dns_class.emit(encoder));
    try!(encoder.emit_i32(self.ttl));

    // TODO: gah... need to write rdata before we know the size of rdata...
    let mut tmp_encoder: BinEncoder = BinEncoder::new(); // making random space
    try!(self.rdata.emit(&mut tmp_encoder));
    let mut tmp_buf = tmp_encoder.as_bytes();

    assert!(tmp_buf.len() <= u16::max_value() as usize);

    try!(encoder.emit_u16(tmp_buf.len() as u16));
    encoder.reserve(tmp_buf.len());

    tmp_buf.reverse();
    while let Some(byte) = tmp_buf.pop() {
      try!(encoder.emit(byte));
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use super::*;

  use ::serialize::binary::*;
  use ::rr::record_data::RData;
  use ::rr::record_type::RecordType;
  use ::rr::dns_class::DNSClass;


  #[test]
  fn test_emit_and_read() {
    let mut record = Record::new();
    record.add_name("www".to_string()).add_name("example".to_string()).add_name("com".to_string())
    .rr_type(RecordType::A).dns_class(DNSClass::IN).ttl(5)
    .rdata(RData::A { address: Ipv4Addr::new(192, 168, 0, 1)});

    let mut encoder = BinEncoder::new();
    record.emit(&mut encoder).unwrap();

    let mut decoder = BinDecoder::new(encoder.as_bytes());

    let got = Record::read(&mut decoder).unwrap();

    assert_eq!(got, record);
  }
}
