/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! resource record implementation

use std::cmp::Ordering;

use serialize::binary::*;
use error::*;
use rr::dns_class::DNSClass;
use rr::domain;
use rr::IntoRecordSet;
use rr::rdata::NULL;
use rr::RData;
use rr::RecordType;
use rr::RecordSet;

/// Resource records are storage value in DNS, into which all key/value pair data is stored.
///
/// [RFC 1035](https://tools.ietf.org/html/rfc1035), DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987
///
/// ```text
/// 4.1.3. Resource record format
///
/// The answer, authority, and additional sections all share the same
/// format: a variable number of resource records, where the number of
/// records is specified in the corresponding count field in the header.
/// Each resource record has the following format:
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                                               /
///     /                      NAME                     /
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     CLASS                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TTL                      |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                   RDLENGTH                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
///     /                     RDATA                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// ```
#[derive(Eq, Ord, Debug, Clone)]
pub struct Record {
    name_labels: domain::Name,
    rr_type: RecordType,
    dns_class: DNSClass,
    ttl: u32,
    rdata: RData,
}

impl Default for Record {
    fn default() -> Self {
        Record {
            // TODO: these really should all be Optionals, I was lazy.
            name_labels: domain::Name::new(),
            rr_type: RecordType::A,
            dns_class: DNSClass::IN,
            ttl: 0,
            rdata: RData::NULL(NULL::new()),
        }
    }
}

impl Record {
    /// Creates a default record, use the setters to build a more useful object.
    ///
    /// There are no optional elements in this object, defaults are an empty name, type A, class IN,
    /// ttl of 0 and the 0.0.0.0 ip address.
    pub fn new() -> Record {
        Default::default()
    }

    /// Create a record with the specified initial values.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the resource records
    /// * `rr_type` - the record type
    /// * `ttl` - time-to-live is the amount of time this record should be cached before refreshing
    pub fn with(name: domain::Name, rr_type: RecordType, ttl: u32) -> Record {
        Record {
            name_labels: name,
            rr_type: rr_type,
            dns_class: DNSClass::IN,
            ttl: ttl,
            rdata: RData::NULL(NULL::new()),
        }
    }

    /// Create a record with the specified initial values.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the resource records
    /// * `rr_type` - the record type
    /// * `ttl` - time-to-live is the amount of time this record should be cached before refreshing
    /// * `rdata` - record data to associate with the Record
    pub fn from_rdata(
        name: domain::Name,
        ttl: u32,
        record_type: RecordType,
        rdata: RData,
    ) -> Record {
        Record {
            name_labels: name,
            rr_type: record_type,
            dns_class: DNSClass::IN,
            ttl: ttl,
            rdata: rdata,
        }
    }

    /// ```text
    /// NAME            a domain name to which this resource record pertains.
    /// ```
    pub fn set_name(&mut self, name: domain::Name) -> &mut Self {
        self.name_labels = name;
        self
    }

    /// ```text
    /// TYPE            two octets containing one of the RR type codes.  This
    ///                 field specifies the meaning of the data in the RDATA
    ///                 field.
    /// ```
    pub fn set_rr_type(&mut self, rr_type: RecordType) -> &mut Self {
        self.rr_type = rr_type;
        self
    }

    /// ```text
    /// CLASS           two octets which specify the class of the data in the
    ///                 RDATA field.
    /// ```
    pub fn set_dns_class(&mut self, dns_class: DNSClass) -> &mut Self {
        self.dns_class = dns_class;
        self
    }

    /// ```text
    /// TTL             a 32 bit unsigned integer that specifies the time
    ///                 interval (in seconds) that the resource record may be
    ///                 cached before it should be discarded.  Zero values are
    ///                 interpreted to mean that the RR can only be used for the
    ///                 transaction in progress, and should not be cached.
    /// ```
    pub fn set_ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = ttl;
        self
    }

    /// ```text
    /// RDATA           a variable length string of octets that describes the
    ///                 resource.  The format of this information varies
    ///                 according to the TYPE and CLASS of the resource record.
    ///                 For example, the if the TYPE is A and the CLASS is IN,
    ///                 the RDATA field is a 4 octet ARPA Internet address.
    /// ```
    pub fn set_rdata(&mut self, rdata: RData) -> &mut Self {
        self.rdata = rdata;
        self
    }

    /// Returns the name of the record
    pub fn name(&self) -> &domain::Name {
        &self.name_labels
    }

    /// Returns the type of the RData in the record
    pub fn rr_type(&self) -> RecordType {
        self.rr_type
    }

    /// Returns the DNSClass of the Record, generally IN fro internet
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Returns the time-to-live of the record, for caching purposes
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the Record Data, i.e. the record information
    pub fn rdata(&self) -> &RData {
        &self.rdata
    }

    /// Returns a mutable reference to the Record Data
    pub fn rdata_mut(&mut self) -> &mut RData {
        &mut self.rdata
    }

    /// Returns the RData consuming the Record
    pub fn unwrap_rdata(self) -> RData {
        self.rdata
    }
}

impl IntoRecordSet for Record {
    fn into_record_set(self) -> RecordSet {
        RecordSet::from(self)
    }
}

impl BinSerializable<Record> for Record {
    /// parse a resource record line example:
    ///  WARNING: the record_bytes is 100% consumed and destroyed in this parsing process
    fn read(decoder: &mut BinDecoder) -> ProtoResult<Record> {
        // NAME            an owner name, i.e., the name of the node to which this
        //                 resource record pertains.
        let name_labels: domain::Name = domain::Name::read(decoder)?;

        // TYPE            two octets containing one of the RR TYPE codes.
        let record_type: RecordType = RecordType::read(decoder)?;

        // CLASS           two octets containing one of the RR CLASS codes.
        let class: DNSClass = if record_type == RecordType::OPT {
            // verify that the OPT record is Root
            if !name_labels.is_root() {
                return Err(ProtoErrorKind::EdnsNameNotRoot(name_labels).into());
            }

            //  DNS Class is overloaded for OPT records in EDNS - RFC 6891
            DNSClass::for_opt(decoder.read_u16()?)
        } else {
            DNSClass::read(decoder)?
        };

        // TTL             a 32 bit signed integer that specifies the time interval
        //                that the resource record may be cached before the source
        //                of the information should again be consulted.  Zero
        //                values are interpreted to mean that the RR can only be
        //                used for the transaction in progress, and should not be
        //                cached.  For example, SOA records are always distributed
        //                with a zero TTL to prohibit caching.  Zero values can
        //                also be used for extremely volatile data.
        // note: u32 seems more accurate given that it can only be positive
        let ttl: u32 = decoder.read_u32()?;

        // RDLENGTH        an unsigned 16 bit integer that specifies the length in
        //                octets of the RDATA field.
        let rd_length: u16 = decoder.read_u16()?;

        // this is to handle updates, RFC 2136, which uses 0 to indicate certain aspects of
        //  pre-requisites
        let rdata: RData = if rd_length == 0 {
            RData::NULL(NULL::new())
        } else {
            // RDATA           a variable length string of octets that describes the
            //                resource.  The format of this information varies
            //                according to the TYPE and CLASS of the resource record.
            RData::read(decoder, record_type, rd_length)?
        };

        Ok(Record {
            name_labels: name_labels,
            rr_type: record_type,
            dns_class: class,
            ttl: ttl,
            rdata: rdata,
        })
    }

    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        self.name_labels.emit(encoder)?;
        self.rr_type.emit(encoder)?;
        self.dns_class.emit(encoder)?;
        encoder.emit_u32(self.ttl)?;

        // gah... need to write rdata before we know the size of rdata...
        // TODO: should we skip the fixed size header and write the rdata first? then write the header?
        let mut tmp_buf: Vec<u8> = Vec::with_capacity(512);
        {
            let mut tmp_encoder: BinEncoder = BinEncoder::with_offset(
                &mut tmp_buf,
                encoder.offset() + 2, /*for u16 len*/
                EncodeMode::Normal,
            );
            self.rdata.emit(&mut tmp_encoder)?;
        }

        assert!(tmp_buf.len() <= u16::max_value() as usize);

        encoder.emit_u16(tmp_buf.len() as u16)?;
        encoder.reserve(tmp_buf.len());

        tmp_buf.reverse();
        while let Some(byte) = tmp_buf.pop() {
            encoder.emit(byte)?;
        }

        Ok(())
    }
}

impl PartialEq for Record {
    /// Equality or records, as defined by
    ///  [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///   1.1.1. Two RRs are considered equal if their NAME, CLASS, TYPE,
    ///   RDLENGTH and RDATA fields are equal.  Note that the time-to-live
    ///   (TTL) field is explicitly excluded from the comparison.
    ///
    ///   1.1.2. The rules for comparison of character strings in names are
    ///   specified in [RFC1035 2.3.3]. i.e. case insensitive
    /// ```
    fn eq(&self, other: &Self) -> bool {
        // self == other && // the same pointer
        self.name_labels == other.name_labels && self.rr_type == other.rr_type
            && self.dns_class == other.dns_class && self.rdata == other.rdata
    }
}

/// returns the value of the compare if the items are greater or lesser, but coninues on equal
macro_rules! compare_or_equal {
  ( $x:ident, $y:ident, $z:ident ) => (
    match $x.$z.partial_cmp(&$y.$z) {
      o @ Some(Ordering::Less) | o @ Some(Ordering::Greater) => return o,
      None => return None,
      Some(Ordering::Equal) => (),
    }
  );
}

impl PartialOrd<Record> for Record {
    /// Canonical ordering as defined by
    ///  [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
    ///
    /// ```text
    /// 6.2.  Canonical RR Form
    ///
    ///    For the purposes of DNS security, the canonical form of an RR is the
    ///    wire format of the RR where:
    ///
    ///    1.  every domain name in the RR is fully expanded (no DNS name
    ///        compression) and fully qualified;
    ///
    ///    2.  all uppercase US-ASCII letters in the owner name of the RR are
    ///        replaced by the corresponding lowercase US-ASCII letters;
    ///
    ///    3.  if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
    ///        HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
    ///        SRV, DNAME, A6, RRSIG, or NSEC, all uppercase US-ASCII letters in
    ///        the DNS names contained within the RDATA are replaced by the
    ///        corresponding lowercase US-ASCII letters;
    ///
    ///    4.  if the owner name of the RR is a wildcard name, the owner name is
    ///        in its original unexpanded form, including the "*" label (no
    ///        wildcard substitution); and
    ///
    ///    5.  the RR's TTL is set to its original value as it appears in the
    ///        originating authoritative zone or the Original TTL field of the
    ///        covering RRSIG RR.
    /// ```
    fn partial_cmp(&self, other: &Record) -> Option<Ordering> {
        // TODO: given that the ordering of Resource Records is dependent on it's binary form and this
        //  method will be used during insertion sort or similar, we should probably do this
        //  conversion once somehow and store it separately. Or should the internal storage of all
        //  resource records be maintained in binary?

        compare_or_equal!(self, other, name_labels);
        compare_or_equal!(self, other, rr_type);
        compare_or_equal!(self, other, dns_class);
        compare_or_equal!(self, other, ttl);
        compare_or_equal!(self, other, rdata);

        // got here, means they are equal
        Some(Ordering::Equal)
    }
}


#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;
    #[allow(unused)]
    use serialize::binary::*;
    use rr::record_data::RData;
    use rr::record_type::RecordType;
    use rr::dns_class::DNSClass;
    use rr::Name;


    #[test]
    fn test_emit_and_read() {
        let mut record = Record::new();
        record
            .set_name(Name::from_str("www.example.com").unwrap())
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_ttl(5)
            .set_rdata(RData::A(Ipv4Addr::new(192, 168, 0, 1)));

        let mut vec_bytes: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut vec_bytes);
            record.emit(&mut encoder).unwrap();
        }

        let mut decoder = BinDecoder::new(&vec_bytes);

        let got = Record::read(&mut decoder).unwrap();

        assert_eq!(got, record);
    }

    #[test]
    fn test_order() {
        let mut record = Record::new();
        record
            .set_name(Name::from_str("www.example.com").unwrap())
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_ttl(5)
            .set_rdata(RData::A(Ipv4Addr::new(192, 168, 0, 1)));

        let mut greater_name = record.clone();
        greater_name.set_name(Name::from_str("zzz.example.com").unwrap());

        let mut greater_type = record.clone();
        greater_type.set_rr_type(RecordType::AAAA);

        let mut greater_class = record.clone();
        greater_class.set_dns_class(DNSClass::NONE);

        let mut greater_rdata = record.clone();
        greater_rdata.set_rdata(RData::A(Ipv4Addr::new(192, 168, 0, 255)));

        let compares = vec![
            (&record, &greater_name),
            (&record, &greater_type),
            (&record, &greater_class),
            (&record, &greater_rdata),
        ];

        assert_eq!(record.clone(), record.clone());
        for (r, g) in compares {
            println!("r, g: {:?}, {:?}", r, g);
            assert_eq!(r.cmp(g), Ordering::Less);
        }
    }
}
