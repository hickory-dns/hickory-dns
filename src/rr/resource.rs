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
  pub fn parse(record_bytes: Vec<u8>) -> Result<Record, FromUtf8Error> {
    // TODO: it would be better to pass iter to all of these methods, but String::from_utf8 makes that complicated
    let mut data: Vec<u8> = record_bytes;
    data.reverse();

    // NAME            an owner name, i.e., the name of the node to which this
    //                 resource record pertains.
    let name_labels: domain::Name = try!(domain::Name::parse(&mut data));

    // TYPE            two octets containing one of the RR TYPE codes.
    let record_type: RecordType = RecordType::parse(&mut data);

    // CLASS           two octets containing one of the RR CLASS codes.
    let class: DNSClass = DNSClass::parse(&mut data);

    // TTL             a 32 bit signed integer that specifies the time interval
    //                that the resource record may be cached before the source
    //                of the information should again be consulted.  Zero
    //                values are interpreted to mean that the RR can only be
    //                used for the transaction in progress, and should not be
    //                cached.  For example, SOA records are always distributed
    //                with a zero TTL to prohibit caching.  Zero values can
    //                also be used for extremely volatile data.
    let ttl: i32 = util::parse_i32(&mut data);

    // RDLENGTH        an unsigned 16 bit integer that specifies the length in
    //                octets of the RDATA field.
    let rd_length: u16 = util::parse_u16(&mut data);

    // RDATA           a variable length string of octets that describes the
    //                resource.  The format of this information varies
    //                according to the TYPE and CLASS of the resource record.
    let rdata = RData::parse(&mut data, &record_type, rd_length);

    Ok(Record{ name_labels: name_labels, rr_type: record_type, dns_class: class, ttl: ttl, rdata: rdata })
  }
}

#[cfg(test)]
mod tests {
}
