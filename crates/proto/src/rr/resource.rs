// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! resource record implementation

use std::{cmp::Ordering, convert::TryFrom, fmt};

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::{
    error::{ProtoError, ProtoErrorKind, ProtoResult},
    rr::{dns_class::DNSClass, Name, RData, RecordData, RecordSet, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict},
};

#[cfg(feature = "dnssec")]
use crate::rr::dnssec::{Proof, Proven};

#[allow(deprecated)]
use crate::rr::IntoRecordSet;

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
/// Resource records are storage value in DNS, into which all key/value pair data is stored.
///
/// # Generic type
/// * `R` - the RecordData type this resource record represents, if unknown at runtime use the `RData` abstract enum type
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
// TODO: make Record carry a lifetime for more efficient storage options in the future
pub struct Record<R: RecordData = RData> {
    name_labels: Name,
    dns_class: DNSClass,
    ttl: u32,
    rdata: R,
    #[cfg(feature = "mdns")]
    mdns_cache_flush: bool,
    #[cfg(feature = "dnssec")]
    proof: Proof,
}

impl Record {
    #[cfg(test)]
    pub fn stub() -> Self {
        Self {
            name_labels: Name::new(),
            dns_class: DNSClass::IN,
            ttl: 0,
            rdata: RData::Update0(RecordType::NULL),
            #[cfg(feature = "mdns")]
            mdns_cache_flush: false,
            #[cfg(feature = "dnssec")]
            proof: Proof::default(),
        }
    }
}

impl Record {
    /// Creates an update record with RDLENGTH=0
    pub fn update0(name: Name, ttl: u32, rr_type: RecordType) -> Self {
        Self {
            name_labels: name,
            dns_class: DNSClass::IN,
            ttl,
            rdata: RData::Update0(rr_type),
            #[cfg(feature = "mdns")]
            mdns_cache_flush: false,
            #[cfg(feature = "dnssec")]
            proof: Proof::default(),
        }
    }

    /// Tries the borrow this record as the specific record type, T
    pub fn try_borrow<T>(&self) -> Option<RecordRef<'_, T>>
    where
        T: RecordData,
    {
        RecordRef::try_from(self).ok()
    }
}

impl<R: RecordData> Record<R> {
    /// Create a record with the specified initial values.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the resource records
    /// * `ttl` - time-to-live is the amount of time this record should be cached before refreshing
    /// * `rdata` - record data to associate with the Record
    pub fn from_rdata(name: Name, ttl: u32, rdata: R) -> Self {
        Self {
            name_labels: name,
            dns_class: DNSClass::IN,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush: false,
            #[cfg(feature = "dnssec")]
            proof: Proof::default(),
        }
    }

    /// Attempts to convert the generic `RData` based Record into this one with the interior `R`
    #[allow(clippy::result_large_err)]
    pub fn try_from(record: Record<RData>) -> Result<Self, Record<RData>> {
        let Record {
            name_labels,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof,
        } = record;

        match R::try_from_rdata(rdata) {
            Ok(rdata) => Ok(Self {
                name_labels,
                dns_class,
                ttl,
                rdata,
                #[cfg(feature = "mdns")]
                mdns_cache_flush,
                #[cfg(feature = "dnssec")]
                proof,
            }),
            Err(rdata) => Err(Record {
                name_labels,
                dns_class,
                ttl,
                rdata,
                #[cfg(feature = "mdns")]
                mdns_cache_flush,
                #[cfg(feature = "dnssec")]
                proof,
            }),
        }
    }

    /// Converts this Record into a generic version of RData
    pub fn into_record_of_rdata(self) -> Record<RData> {
        let Self {
            name_labels,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof,
        } = self;

        let rdata: RData = RecordData::into_rdata(rdata);

        Record {
            name_labels,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof,
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
    #[track_caller]
    pub fn set_data(&mut self, rdata: R) -> &mut Self {
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

    /// Set the DNSSEC Proof for this record, after it's been verified
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub fn set_proof(&mut self, proof: Proof) -> &mut Self {
        self.proof = proof;
        self
    }

    /// Returns the name of the record
    #[inline]
    pub fn name(&self) -> &Name {
        &self.name_labels
    }

    /// Returns the type of the RecordData in the record
    #[inline]
    pub fn record_type(&self) -> RecordType {
        self.rdata.record_type()
    }

    /// Returns the DNSClass of the Record, generally IN fro internet
    #[inline]
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Returns the time-to-live of the record, for caching purposes
    #[inline]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the Record Data, i.e. the record information
    #[inline]
    pub fn data(&self) -> &R {
        &self.rdata
    }

    /// Returns a mutable reference to the Record Data
    #[inline]
    pub fn data_mut(&mut self) -> &mut R {
        &mut self.rdata
    }

    /// Returns the RData consuming the Record
    #[inline]
    pub fn into_data(self) -> R {
        self.rdata
    }

    /// Consumes `Record` and returns its components
    #[inline]
    pub fn into_parts(self) -> RecordParts {
        let this = self.into_record_of_rdata();
        this.into()
    }

    /// Returns if the mDNS cache-flush bit is set or not
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    #[inline]
    pub fn mdns_cache_flush(&self) -> bool {
        self.mdns_cache_flush
    }

    /// The Proof of DNSSEC validation for this record, this is only valid if some form of validation has occurred
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    #[inline]
    pub fn proof(&self) -> Proof {
        self.proof
    }
}

/// Consumes `Record` giving public access to fields of `Record` so they can
/// be destructured and taken by value
pub struct RecordParts<R: RecordData = RData> {
    /// label names
    pub name_labels: Name,
    /// dns class
    pub dns_class: DNSClass,
    /// time to live
    pub ttl: u32,
    /// rdata
    pub rdata: R,
    /// mDNS cache flush
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    pub mdns_cache_flush: bool,
    /// mDNS cache flush
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    pub proof: Proof,
}

impl<R: RecordData> From<Record<R>> for RecordParts<R> {
    fn from(record: Record<R>) -> Self {
        let Record {
            name_labels,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof,
        } = record;

        Self {
            name_labels,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof,
        }
    }
}

#[allow(deprecated)]
impl IntoRecordSet for Record {
    fn into_record_set(self) -> RecordSet {
        RecordSet::from(self)
    }
}

impl<R: RecordData> BinEncodable for Record<R> {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        self.name_labels.emit(encoder)?;
        self.record_type().emit(encoder)?;

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
        if !self.rdata.is_update() {
            self.rdata.emit(encoder)?;
        }

        // get the length written
        let len = encoder.len_since_place(&place);
        assert!(len <= u16::MAX as usize);

        // replace the location with the length
        place.replace(encoder, len as u16)?;
        Ok(())
    }
}

impl<'r> BinDecodable<'r> for Record<RData> {
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
                    DNSClass::from(dns_class_value & !MDNS_ENABLE_CACHE_FLUSH)
                } else {
                    DNSClass::from(dns_class_value)
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
            RData::Update0(record_type)
        } else {
            // RDATA           a variable length string of octets that describes the
            //                resource.  The format of this information varies
            //                according to the TYPE and CLASS of the resource record.
            // Adding restrict to the rdata length because it's used for many calculations later
            //  and must be validated before hand
            RData::read(decoder, record_type, Restrict::new(rd_length))?
        };

        Ok(Self {
            name_labels,
            dns_class: class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof: Proof::default(),
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
impl<R: RecordData> fmt::Display for Record<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{name} {ttl} {class} {ty} {rdata}",
            name = self.name_labels,
            ttl = self.ttl,
            class = self.dns_class,
            ty = self.record_type(),
            rdata = self.rdata,
        )?;

        Ok(())
    }
}

impl<R: RecordData> PartialEq for Record<R> {
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
            && self.dns_class == other.dns_class
            && self.rdata == other.rdata
    }
}

/// returns the value of the compare if the items are greater or lesser, but continues on equal
macro_rules! compare_or_equal {
    ($x:ident, $y:ident, $z:ident) => {
        match ($x).$z.cmp(&($y).$z) {
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
        match self.record_type().cmp(&other.record_type()) {
            o @ Ordering::Less | o @ Ordering::Greater => return o,
            Ordering::Equal => {}
        }
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

#[cfg(feature = "dnssec")]
impl From<Record> for Proven<Record> {
    fn from(record: Record) -> Self {
        let proof = record.proof();
        Self::new(proof, record)
    }
}

#[cfg(feature = "dnssec")]
impl<'a> From<&'a Record> for Proven<&'a Record> {
    fn from(record: &'a Record) -> Self {
        let proof = record.proof();
        Self::new(proof, record)
    }
}

/// A Record where the RecordData type is already known
pub struct RecordRef<'a, R: RecordData> {
    name_labels: &'a Name,
    dns_class: DNSClass,
    ttl: u32,
    rdata: &'a R,
    #[cfg(feature = "mdns")]
    mdns_cache_flush: bool,
    #[cfg(feature = "dnssec")]
    proof: Proof,
}

impl<'a, R: RecordData> Clone for RecordRef<'a, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, R: RecordData> Copy for RecordRef<'a, R> {}

impl<'a, R: RecordData> RecordRef<'a, R> {
    /// Allocates space for a Record with the same fields
    pub fn to_owned(&self) -> Record<R> {
        Record {
            name_labels: self.name_labels.to_owned(),
            dns_class: self.dns_class,
            ttl: self.ttl,
            rdata: self.rdata.clone(),
            #[cfg(feature = "mdns")]
            mdns_cache_flush: self.mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof: self.proof,
        }
    }

    /// Returns the name of the record
    #[inline]
    pub fn name(&self) -> &Name {
        self.name_labels
    }

    /// Returns the type of the RecordData in the record
    #[inline]
    pub fn record_type(&self) -> RecordType {
        self.rdata.record_type()
    }

    /// Returns the DNSClass of the Record, generally IN fro internet
    #[inline]
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Returns the time-to-live of the record, for caching purposes
    #[inline]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the Record Data, i.e. the record information
    #[inline]
    pub fn data(&self) -> &R {
        self.rdata
    }

    /// Returns if the mDNS cache-flush bit is set or not
    /// See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-10.2)
    #[cfg(feature = "mdns")]
    #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
    #[inline]
    pub fn mdns_cache_flush(&self) -> bool {
        self.mdns_cache_flush
    }

    /// The Proof of DNSSEC validation for this record, this is only valid if some form of validation has occurred
    #[cfg(feature = "dnssec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dnssec")))]
    #[inline]
    pub fn proof(&self) -> Proof {
        self.proof
    }
}

impl<'a, R: RecordData> TryFrom<&'a Record> for RecordRef<'a, R> {
    type Error = &'a Record;

    fn try_from(record: &'a Record) -> Result<Self, Self::Error> {
        let Record {
            name_labels,
            dns_class,
            ttl,
            rdata,
            #[cfg(feature = "mdns")]
            mdns_cache_flush,
            #[cfg(feature = "dnssec")]
            proof,
        } = record;

        match R::try_borrow(rdata) {
            None => Err(record),
            Some(rdata) => Ok(Self {
                name_labels,
                dns_class: *dns_class,
                ttl: *ttl,
                rdata,
                #[cfg(feature = "mdns")]
                mdns_cache_flush: *mdns_cache_flush,
                #[cfg(feature = "dnssec")]
                proof: *proof,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::cmp::Ordering;
    use std::str::FromStr;

    use super::*;
    use crate::rr::dns_class::DNSClass;
    use crate::rr::rdata::{A, AAAA};
    use crate::rr::record_data::RData;
    use crate::rr::Name;
    #[allow(clippy::useless_attribute)]
    #[allow(unused)]
    use crate::serialize::binary::*;

    #[test]
    fn test_emit_and_read() {
        let record = Record::from_rdata(
            Name::from_str("www.example.com").unwrap(),
            5,
            RData::A(A::new(192, 168, 0, 1)),
        );

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
        let mut record = Record::from_rdata(
            Name::from_str("www.example.com").unwrap(),
            5,
            RData::A(A::new(192, 168, 0, 1)),
        );
        record.set_dns_class(DNSClass::IN);

        let mut greater_name = record.clone();
        greater_name.set_name(Name::from_str("zzz.example.com").unwrap());

        let mut greater_type = record.clone().into_record_of_rdata();
        greater_type.set_data(RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 0)));

        let mut greater_class = record.clone();
        greater_class.set_dns_class(DNSClass::NONE);

        let mut greater_rdata = record.clone();
        greater_rdata.set_data(RData::A(A::new(192, 168, 0, 255)));

        let compares = vec![
            (&record, &greater_name),
            (&record, &greater_type),
            (&record, &greater_class),
            (&record, &greater_rdata),
        ];

        assert_eq!(record.clone(), record.clone());
        for (r, g) in compares {
            println!("r, g: {r:?}, {g:?}");
            assert_eq!(r.cmp(g), Ordering::Less);
        }
    }

    #[cfg(feature = "mdns")]
    #[test]
    fn test_mdns_cache_flush_bit_handling() {
        const RR_CLASS_OFFSET: usize = 1 /* empty name */ +
            std::mem::size_of::<u16>() /* rr_type */;

        let mut record = Record::<RData>::stub();
        record.set_mdns_cache_flush(true);

        let mut vec_bytes: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut vec_bytes);
            record.emit(&mut encoder).unwrap();

            let rr_class_slice = encoder.slice_of(RR_CLASS_OFFSET, RR_CLASS_OFFSET + 2);
            assert_eq!(rr_class_slice, &[0x80, 0x01]);
        }

        let mut decoder = BinDecoder::new(&vec_bytes);

        let got = Record::<RData>::read(&mut decoder).unwrap();

        assert_eq!(got.dns_class(), DNSClass::IN);
        assert!(got.mdns_cache_flush());
    }
}
