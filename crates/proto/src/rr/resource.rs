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
use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::dns_class::DNSClass;
use crate::rr::rdata::NULL;
#[allow(deprecated)]
use crate::rr::IntoRecordSet;
use crate::rr::Name;
use crate::rr::RData;
use crate::rr::RecordSet;
use crate::rr::RecordType;
use crate::serialize::binary::*;

#[cfg(feature = "mdns")]
/// From [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
/// ```text
/// The cache-flush bit is the most significant bit of the second
/// 16-bit word of a resource record in a Resource Record Section of a
/// Multicast DNS message (the field conventionally referred to as the
/// rrclass field), and the actual resource record class is the least
/// significant fifteen bits of this field.
/// ```
const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;

const NULL_RDATA: &RData = &RData::NULL(NULL::new());
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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Eq, Debug, Clone)]
pub struct Record {
    name_labels: Name,
    rr_type: RecordType,
    dns_class: DNSClass,
    ttl: u32,
    rdata: Option<RData>,
    #[cfg(feature = "mdns")]
    mdns_cache_flush: bool,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            // TODO: these really should all be Optionals, I was lazy.
            name_labels: Name::new(),
            rr_type: RecordType::NULL,
            dns_class: DNSClass::IN,
            ttl: 0,
            rdata: None,
            #[cfg(feature = "mdns")]
            mdns_cache_flush: false,
        }
    }
}

impl Record {
    /// Creates a default record, use the setters to build a more useful object.
    ///
    /// There are no optional elements in this object, defaults are an empty name, type A, class IN,
    /// ttl of 0 and the 0.0.0.0 ip address.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a record with the specified initial values.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the resource records
    /// * `rr_type` - the record type
    /// * `ttl` - time-to-live is the amount of time this record should be cached before refreshing
    pub fn with(name: Name, rr_type: RecordType, ttl: u32) -> Self {
        Self {
            name_labels: name,
            rr_type,
            dns_class: DNSClass::IN,
            ttl,
            rdata: None,
            #[cfg(feature = "mdns")]
            mdns_cache_flush: false,
        }
    }

    /// Create a record with the specified initial values.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the resource records
    /// * `ttl` - time-to-live is the amount of time this record should be cached before refreshing
    /// * `rdata` - record data to associate with the Record
    pub fn from_rdata(name: Name, ttl: u32, rdata: RData) -> Self {
        Self {
            name_labels: name,
            rr_type: rdata.to_record_type(),
            dns_class: DNSClass::IN,
            ttl,
            rdata: Some(rdata),
            #[cfg(feature = "mdns")]
            mdns_cache_flush: false,
        }
    }

    /// ```text
    /// NAME            a domain name to which this resource record pertains.
    /// ```
    pub fn set_name(&mut self, name: Name) -> &mut Self {
        self.name_labels = name;
        self
    }

    /// ```text
    /// TYPE            two octets containing one of the RR type codes.  This
    ///                 field specifies the meaning of the data in the RDATA
    ///                 field.
    /// ```
    // #[deprecated(note = "use `Record::set_record_type`")]
    pub fn set_rr_type(&mut self, rr_type: RecordType) -> &mut Self {
        self.rr_type = rr_type;
        self
    }

    /// ```text
    /// TYPE            two octets containing one of the RR type codes.  This
    ///                 field specifies the meaning of the data in the RDATA
    ///                 field.
    /// ```
    pub fn set_record_type(&mut self, rr_type: RecordType) -> &mut Self {
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
    #[deprecated(note = "use `Record::set_data` instead")]
    pub fn set_rdata(&mut self, rdata: RData) -> &mut Self {
        self.rdata = Some(rdata);
        self
    }

    /// ```text
    /// RDATA           a variable length string of octets that describes the
    ///                 resource.  The format of this information varies
    ///                 according to the TYPE and CLASS of the resource record.
    ///                 For example, the if the TYPE is A and the CLASS is IN,
    ///                 the RDATA field is a 4 octet ARPA Internet address.
    /// ```
    #[allow(deprecated)]
    pub fn set_data(&mut self, rdata: Option<RData>) -> &mut Self {
        debug_assert!(
            !(matches!(&rdata, Some(RData::ZERO))
                && matches!(&rdata, Some(RData::NULL(null)) if null.anything().is_empty())),
            "pass None rather than ZERO or NULL"
        );
        self.rdata = rdata;
        self
    }

    /// Changes mDNS cache-flush bit
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub fn set_mdns_cache_flush(&mut self, flag: bool) -> &mut Self {
        self.mdns_cache_flush = flag;
        self
    }

    /// Returns the name of the record
    pub fn name(&self) -> &Name {
        &self.name_labels
    }

    /// Returns the type of the RData in the record
    // #[deprecated(note = "use `Record::record_type`")]
    pub fn rr_type(&self) -> RecordType {
        self.rr_type
    }

    /// Returns the type of the RecordData in the record
    pub fn record_type(&self) -> RecordType {
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
    #[deprecated(note = "use `Record::data` instead")]
    pub fn rdata(&self) -> &RData {
        if let Some(ref rdata) = &self.rdata {
            rdata
        } else {
            NULL_RDATA
        }
    }

    /// Returns the Record Data, i.e. the record information
    pub fn data(&self) -> Option<&RData> {
        self.rdata.as_ref()
    }

    /// Returns if the mDNS cache-flush bit is set or not
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub fn mdns_cache_flush(&self) -> bool {
        self.mdns_cache_flush
    }

    /// Returns a mutable reference to the Record Data
    pub fn data_mut(&mut self) -> Option<&mut RData> {
        self.rdata.as_mut()
    }

    /// Returns the RData consuming the Record
    pub fn into_data(self) -> Option<RData> {
        self.rdata
    }

    /// Consumes `Record` and returns its components
    pub fn into_parts(self) -> RecordParts {
        self.into()
    }
}

/// Consumes `Record` giving public access to fields of `Record` so they can
/// be destructured and taken by value
pub struct RecordParts {
    /// label names
    pub name_labels: Name,
    /// record type
    pub rr_type: RecordType,
    /// dns class
    pub dns_class: DNSClass,
    /// time to live
    pub ttl: u32,
    /// rdata
    pub rdata: Option<RData>,
    /// mDNS cache flush
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub mdns_cache_flush: bool,
}

impl From<Record> for RecordParts {
    fn from(record: Record) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(feature = "mdns")] {
                let Record {
                    name_labels,
                    rr_type,
                    dns_class,
                    ttl,
                    rdata,
                    mdns_cache_flush,
                } = record;
            } else {
                let Record {
                    name_labels,
                    rr_type,
                    dns_class,
                    ttl,
                    rdata,
                } = record;
            }
        }

        Self {
            name_labels,
            rr_type,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
        }
    }
}

#[allow(deprecated)]
impl IntoRecordSet for Record {
    fn into_record_set(self) -> RecordSet {
        RecordSet::from(self)
    }
}

impl BinEncodable for Record {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.name_labels.emit(encoder)?;
        self.rr_type.emit(encoder)?;

        #[cfg(not(feature = "mdns"))]
        self.dns_class.emit(encoder)?;

        #[cfg(feature = "mdns")]
        {
            if self.mdns_cache_flush {
                encoder.emit_u16(u16::from(self.dns_class()) | MDNS_ENABLE_CACHE_FLUSH)?;
            } else {
                self.dns_class.emit(encoder)?;
            }
        }

        encoder.emit_u32(self.ttl)?;

        // place the RData length
        let place = encoder.place::<u16>()?;

        // write the RData
        //   the None case is handled below by writing `0` for the length of the RData
        //   this is in turn read as `None` during the `read` operation.
        if let Some(rdata) = &self.rdata {
            rdata.emit(encoder)?;
        }

        // get the length written
        let len = encoder.len_since_place(&place);
        assert!(len <= u16::max_value() as usize);

        // replace the location with the length
        place.replace(encoder, len as u16)?;
        Ok(())
    }
}

impl<'r> BinDecodable<'r> for Record {
    /// parse a resource record line example:
    ///  WARNING: the record_bytes is 100% consumed and destroyed in this parsing process
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        // NAME            an owner name, i.e., the name of the node to which this
        //                 resource record pertains.
        let name_labels: Name = Name::read(decoder)?;

        // TYPE            two octets containing one of the RR TYPE codes.
        let record_type: RecordType = RecordType::read(decoder)?;

        #[cfg(feature = "mdns")]
        let mut mdns_cache_flush = false;

        // CLASS           two octets containing one of the RR CLASS codes.
        let class: DNSClass = if record_type == RecordType::OPT {
            // verify that the OPT record is Root
            if !name_labels.is_root() {
                return Err(ProtoErrorKind::EdnsNameNotRoot(name_labels).into());
            }

            //  DNS Class is overloaded for OPT records in EDNS - RFC 6891
            DNSClass::for_opt(
                decoder.read_u16()?.unverified(/*restricted to a min of 512 in for_opt*/),
            )
        } else {
            #[cfg(not(feature = "mdns"))]
            {
                DNSClass::read(decoder)?
            }

            #[cfg(feature = "mdns")]
            {
                let dns_class_value =
                    decoder.read_u16()?.unverified(/*DNSClass::from_u16 will verify the value*/);
                if dns_class_value & MDNS_ENABLE_CACHE_FLUSH > 0 {
                    mdns_cache_flush = true;
                    DNSClass::from_u16(dns_class_value & !MDNS_ENABLE_CACHE_FLUSH)?
                } else {
                    DNSClass::from_u16(dns_class_value)?
                }
            }
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
        let ttl: u32 = decoder.read_u32()?.unverified(/*any u32 is valid*/);

        // RDLENGTH        an unsigned 16 bit integer that specifies the length in
        //                octets of the RDATA field.
        let rd_length = decoder
            .read_u16()?
            .verify_unwrap(|u| (*u as usize) <= decoder.len())
            .map_err(|u| {
                ProtoError::from(format!(
                    "rdata length too large for remaining bytes, need: {} remain: {}",
                    u,
                    decoder.len()
                ))
            })?;

        // this is to handle updates, RFC 2136, which uses 0 to indicate certain aspects of pre-requisites
        //   Null represents any data.
        let rdata = if rd_length == 0 {
            None
        } else {
            // RDATA           a variable length string of octets that describes the
            //                resource.  The format of this information varies
            //                according to the TYPE and CLASS of the resource record.
            // Adding restrict to the rdata length because it's used for many calculations later
            //  and must be validated before hand
            Some(RData::read(decoder, record_type, Restrict::new(rd_length))?)
        };

        Ok(Self {
            name_labels,
            rr_type: record_type,
            dns_class: class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
        })
    }
}

/// [RFC 1033](https://tools.ietf.org/html/rfc1033), DOMAIN OPERATIONS GUIDE, November 1987
///
/// ```text
///   RESOURCE RECORDS
///
///   Records in the zone data files are called resource records (RRs).
///   They are specified in RFC-883 and RFC-973.  An RR has a standard
///   format as shown:
///
///           <name>   [<ttl>]   [<class>]   <type>   <data>
///
///   The record is divided into fields which are separated by white space.
///
///      <name>
///
///         The name field defines what domain name applies to the given
///         RR.  In some cases the name field can be left blank and it will
///         default to the name field of the previous RR.
///
///      <ttl>
///
///         TTL stands for Time To Live.  It specifies how long a domain
///         resolver should cache the RR before it throws it out and asks a
///         domain server again.  See the section on TTL's.  If you leave
///         the TTL field blank it will default to the minimum time
///         specified in the SOA record (described later).
///
///      <class>
///
///         The class field specifies the protocol group.  If left blank it
///         will default to the last class specified.
///
///      <type>
///
///         The type field specifies what type of data is in the RR.  See
///         the section on types.
///
///      <data>
///
///         The data field is defined differently for each type and class
///         of data.  Popular RR data formats are described later.
/// ```
impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{name} {ttl} {class} {ty}",
            name = self.name_labels,
            ttl = self.ttl,
            class = self.dns_class,
            ty = self.rr_type,
        )?;

        if let Some(rdata) = &self.rdata {
            write!(f, " {rdata}", rdata = rdata)?;
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
        self.name_labels == other.name_labels
            && self.rr_type == other.rr_type
            && self.dns_class == other.dns_class
            && self.rdata == other.rdata
    }
}

/// returns the value of the compare if the items are greater or lesser, but continues on equal
macro_rules! compare_or_equal {
    ($x:ident, $y:ident, $z:ident) => {
        match $x.$z.cmp(&$y.$z) {
            o @ Ordering::Less | o @ Ordering::Greater => return o,
            Ordering::Equal => (),
        }
    };
}

impl Ord for Record {
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
    fn cmp(&self, other: &Self) -> Ordering {
        // TODO: given that the ordering of Resource Records is dependent on it's binary form and this
        //  method will be used during insertion sort or similar, we should probably do this
        //  conversion once somehow and store it separately. Or should the internal storage of all
        //  resource records be maintained in binary?

        compare_or_equal!(self, other, name_labels);
        compare_or_equal!(self, other, rr_type);
        compare_or_equal!(self, other, dns_class);
        compare_or_equal!(self, other, ttl);
        compare_or_equal!(self, other, rdata);
        Ordering::Equal
    }
}

impl PartialOrd<Self> for Record {
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
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::cmp::Ordering;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;
    use crate::rr::dns_class::DNSClass;
    use crate::rr::record_data::RData;
    use crate::rr::record_type::RecordType;
    use crate::rr::Name;
    #[allow(clippy::useless_attribute)]
    #[allow(unused)]
    use crate::serialize::binary::*;

    #[test]
    fn test_emit_and_read() {
        let mut record = Record::new();
        record
            .set_name(Name::from_str("www.example.com").unwrap())
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_ttl(5)
            .set_data(Some(RData::A(Ipv4Addr::new(192, 168, 0, 1))));

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
            .set_data(Some(RData::A(Ipv4Addr::new(192, 168, 0, 1))));

        let mut greater_name = record.clone();
        greater_name.set_name(Name::from_str("zzz.example.com").unwrap());

        let mut greater_type = record.clone();
        greater_type.set_rr_type(RecordType::AAAA);

        let mut greater_class = record.clone();
        greater_class.set_dns_class(DNSClass::NONE);

        let mut greater_rdata = record.clone();
        greater_rdata.set_data(Some(RData::A(Ipv4Addr::new(192, 168, 0, 255))));

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

    #[cfg(feature = "mdns")]
    #[test]
    fn test_mdns_cache_flush_bit_handling() {
        const RR_CLASS_OFFSET: usize = 1 /* empty name */ +
            std::mem::size_of::<u16>() /* rr_type */;

        let mut record = Record::new();
        record.set_mdns_cache_flush(true);

        let mut vec_bytes: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut vec_bytes);
            record.emit(&mut encoder).unwrap();

            let rr_class_slice = encoder.slice_of(RR_CLASS_OFFSET, RR_CLASS_OFFSET + 2);
            assert_eq!(rr_class_slice, &[0x80, 0x01]);
        }

        let mut decoder = BinDecoder::new(&vec_bytes);

        let got = Record::read(&mut decoder).unwrap();

        assert_eq!(got.dns_class(), DNSClass::IN);
        assert!(got.mdns_cache_flush());
    }
}
