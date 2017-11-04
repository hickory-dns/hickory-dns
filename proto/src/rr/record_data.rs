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

//! record data enum variants

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::convert::From;
use std::cmp::Ordering;

use error::*;
use serialize::binary::*;
use super::domain::Name;
use super::record_type::RecordType;
use super::rdata;
use super::rdata::{CAA, MX, NULL, OPT, SOA, SRV, TXT};

#[cfg(feature = "dnssec")]
use super::dnssec::rdata::DNSSECRData;

/// Record data enum variants
///
/// [RFC 1035](https://tools.ietf.org/html/rfc1035), DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987
///
/// ```text
/// 3.3. Standard RRs
///
/// The following RR definitions are expected to occur, at least
/// potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
/// will be used in all classes, and have the same format in all classes.
/// Because their RDATA format is known, all domain names in the RDATA
/// section of these RRs may be compressed.
///
/// <domain-name> is a domain name represented as a series of labels, and
/// terminated by a label with zero length.  <character-string> is a single
/// length octet followed by that number of characters.  <character-string>
/// is treated as binary information, and can be up to 256 characters in
/// length (including the length octet).
/// ```
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum RData {
    /// ```text
    /// -- RFC 1035 -- Domain Implementation and Specification    November 1987
    ///
    /// 3.4. Internet specific RRs
    ///
    /// 3.4.1. A RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    ADDRESS                    |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// ADDRESS         A 32 bit Internet address.
    ///
    /// Hosts that have multiple Internet addresses will have multiple A
    /// records.
    ///
    /// A records cause no additional section processing.  The RDATA section of
    /// an A line in a master file is an Internet address expressed as four
    /// decimal numbers separated by dots without any imbedded spaces (e.g.,
    /// "10.2.0.52" or "192.0.5.6").
    /// ```
    A(Ipv4Addr),

    /// ```text
    /// -- RFC 1886 -- IPv6 DNS Extensions              December 1995
    ///
    /// 2.2 AAAA data format
    ///
    ///    A 128 bit IPv6 address is encoded in the data portion of an AAAA
    ///    resource record in network byte order (high-order byte first).
    /// ```
    AAAA(Ipv6Addr),

    /// ```text
    /// -- RFC 6844          Certification Authority Authorization     January 2013
    ///
    /// 5.1.  Syntax
    ///
    /// A CAA RR contains a single property entry consisting of a tag-value
    /// pair.  Each tag represents a property of the CAA record.  The value
    /// of a CAA property is that specified in the corresponding value field.
    ///
    /// A domain name MAY have multiple CAA RRs associated with it and a
    /// given property MAY be specified more than once.
    ///
    /// The CAA data field contains one property entry.  A property entry
    /// consists of the following data fields:
    ///
    /// +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
    /// | Flags          | Tag Length = n |
    /// +----------------+----------------+...+---------------+
    /// | Tag char 0     | Tag char 1     |...| Tag char n-1  |
    /// +----------------+----------------+...+---------------+
    /// +----------------+----------------+.....+----------------+
    /// | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
    /// +----------------+----------------+.....+----------------+

    /// Where n is the length specified in the Tag length field and m is the
    /// remaining octets in the Value field (m = d - n - 2) where d is the
    /// length of the RDATA section.
    /// ```
    CAA(CAA),
  
    /// ```text
    ///   3.3. Standard RRs
    ///
    /// The following RR definitions are expected to occur, at least
    /// potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
    /// will be used in all classes, and have the same format in all classes.
    /// Because their RDATA format is known, all domain names in the RDATA
    /// section of these RRs may be compressed.
    ///
    /// <domain-name> is a domain name represented as a series of labels, and
    /// terminated by a label with zero length.  <character-string> is a single
    /// length octet followed by that number of characters.  <character-string>
    /// is treated as binary information, and can be up to 256 characters in
    /// length (including the length octet).
    ///
    /// 3.3.1. CNAME RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                     CNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// CNAME           A <domain-name> which specifies the canonical or primary
    ///                 name for the owner.  The owner name is an alias.
    ///
    /// CNAME RRs cause no additional section processing, but name servers may
    /// choose to restart the query at the canonical name in certain cases.  See
    /// the description of name server logic in [RFC-1034] for details.
    /// ```
    CNAME(Name),

    /// ```text
    /// 3.3.9. MX RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                  PREFERENCE                   |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   EXCHANGE                    /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ////
    /// where:
    ///
    /// PREFERENCE      A 16 bit integer which specifies the preference given to
    ///                 this RR among others at the same owner.  Lower values
    ///                 are preferred.
    ///
    /// EXCHANGE        A <domain-name> which specifies a host willing to act as
    ///                 a mail exchange for the owner name.
    ///
    /// MX records cause type A additional section processing for the host
    /// specified by EXCHANGE.  The use of MX RRs is explained in detail in
    /// [RFC-974].
    /// ```
    MX(MX),

    /// ```text
    /// 3.3.10. NULL RDATA format (EXPERIMENTAL)
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                  <anything>                   /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// Anything at all may be in the RDATA field so long as it is 65535 octets
    /// or less.
    ///
    /// NULL records cause no additional section processing.  NULL RRs are not
    /// allowed in master files.  NULLs are used as placeholders in some
    /// experimental extensions of the DNS.
    /// ```
    NULL(NULL),

    /// ```text
    /// 3.3.11. NS RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   NSDNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// NSDNAME         A <domain-name> which specifies a host which should be
    ///                 authoritative for the specified class and domain.
    ///
    /// NS records cause both the usual additional section processing to locate
    /// a type A record, and, when used in a referral, a special search of the
    /// zone in which they reside for glue information.
    ///
    /// The NS RR states that the named host should be expected to have a zone
    /// starting at owner name of the specified class.  Note that the class may
    /// not indicate the protocol family which should be used to communicate
    /// with the host, although it is typically a strong hint.  For example,
    /// hosts which are name servers for either Internet (IN) or Hesiod (HS)
    /// class information are normally queried using IN class protocols.
    /// ```
    NS(Name),

    /// ```text
    /// RFC 6891                   EDNS(0) Extensions                 April 2013
    /// 6.1.2.  Wire Format
    ///
    ///        +------------+--------------+------------------------------+
    ///        | Field Name | Field Type   | Description                  |
    ///        +------------+--------------+------------------------------+
    ///        | NAME       | domain name  | MUST be 0 (root domain)      |
    ///        | TYPE       | u_int16_t    | OPT (41)                     |
    ///        | CLASS      | u_int16_t    | requestor's UDP payload size |
    ///        | TTL        | u_int32_t    | extended RCODE and flags     |
    ///        | RDLEN      | u_int16_t    | length of all RDATA          |
    ///        | RDATA      | octet stream | {attribute,value} pairs      |
    ///        +------------+--------------+------------------------------+
    ///
    /// The variable part of an OPT RR may contain zero or more options in
    ///    the RDATA.  Each option MUST be treated as a bit field.  Each option
    ///    is encoded as:
    ///
    ///                   +0 (MSB)                            +1 (LSB)
    ///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    ///     0: |                          OPTION-CODE                          |
    ///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    ///     2: |                         OPTION-LENGTH                         |
    ///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    ///     4: |                                                               |
    ///        /                          OPTION-DATA                          /
    ///        /                                                               /
    ///        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /// ```
    OPT(OPT),

    /// ```text
    /// 3.3.12. PTR RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   PTRDNAME                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// PTRDNAME        A <domain-name> which points to some location in the
    ///                 domain name space.
    ///
    /// PTR records cause no additional section processing.  These RRs are used
    /// in special domains to point to some other location in the domain space.
    /// These records are simple data, and don't imply any special processing
    /// similar to that performed by CNAME, which identifies aliases.  See the
    /// description of the IN-ADDR.ARPA domain for an example.
    /// ```
    PTR(Name),

    /// ```text
    /// 3.3.13. SOA RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                     MNAME                     /
    ///     /                                               /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                     RNAME                     /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    SERIAL                     |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    REFRESH                    |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                     RETRY                     |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    EXPIRE                     |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     |                    MINIMUM                    |
    ///     |                                               |
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// MNAME           The <domain-name> of the name server that was the
    ///                 original or primary source of data for this zone.
    ///
    /// RNAME           A <domain-name> which specifies the mailbox of the
    ///                 person responsible for this zone.
    ///
    //// SERIAL          The unsigned 32 bit version number of the original copy
    ///                 of the zone.  Zone transfers preserve this value.  This
    ///                 value wraps and should be compared using sequence space
    ///                 arithmetic.
    ///
    /// REFRESH         A 32 bit time interval before the zone should be
    ///                 refreshed.
    ///
    /// RETRY           A 32 bit time interval that should elapse before a
    ///                 failed refresh should be retried.
    ///
    /// EXPIRE          A 32 bit time value that specifies the upper limit on
    ///                 the time interval that can elapse before the zone is no
    ///                 longer authoritative.
    ///
    /// MINIMUM         The unsigned 32 bit minimum TTL field that should be
    ///                 exported with any RR from this zone.
    ///
    /// SOA records cause no additional section processing.
    ///
    /// All times are in units of seconds.
    ///
    /// Most of these fields are pertinent only for name server maintenance
    /// operations.  However, MINIMUM is used in all query operations that
    /// retrieve RRs from a zone.  Whenever a RR is sent in a response to a
    /// query, the TTL field is set to the maximum of the TTL field from the RR
    /// and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
    /// bound on the TTL field for all RRs in a zone.  Note that this use of
    /// MINIMUM should occur when the RRs are copied into the response and not
    /// when the zone is loaded from a master file or via a zone transfer.  The
    /// reason for this provison is to allow future dynamic update facilities to
    /// change the SOA RR with known semantics.
    /// ```
    SOA(SOA),

    /// ```text
    /// RFC 2782                       DNS SRV RR                  February 2000
    ///
    /// The format of the SRV RR
    ///
    ///  _Service._Proto.Name TTL Class SRV Priority Weight Port Target
    /// ```
    SRV(SRV),

    /// ```text
    /// 3.3.14. TXT RDATA format
    ///
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///     /                   TXT-DATA                    /
    ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// where:
    ///
    /// TXT-DATA        One or more <character-string>s.
    ///
    /// TXT RRs are used to hold descriptive text.  The semantics of the text
    /// depends on the domain where it is found.
    /// ```
    TXT(TXT),

    /// A DNSSEC- or SIG(0)- specific record. See `DNSSECRData` for details.
    ///
    /// These types are in `DNSSECRData` to make them easy to disable when
    /// crypto functionality isn't needed.
    #[cfg(feature = "dnssec")]
    DNSSEC(DNSSECRData),
}

impl RData {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
            self.emit(&mut encoder).unwrap_or_else(|_| {
                warn!("could not encode RDATA: {:?}", self);
                ()
            });
        }
        buf
    }

    /// Read the RData from the given Decoder
    pub fn read(
        decoder: &mut BinDecoder,
        record_type: RecordType,
        rdata_length: u16,
    ) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        let result = match record_type {
            RecordType::A => {
                debug!("reading A");
                RData::A(rdata::a::read(decoder)?)
            }
            RecordType::AAAA => {
                debug!("reading AAAA");
                RData::AAAA(rdata::aaaa::read(decoder)?)
            }
            rt @ RecordType::ANY => {
                return Err(ProtoErrorKind::UnknownRecordTypeValue(rt.into()).into())
            }
            rt @ RecordType::AXFR => {
                return Err(ProtoErrorKind::UnknownRecordTypeValue(rt.into()).into())
            }
            RecordType::CAA => {
                debug!("reading CAA");
                rdata::caa::read(decoder, rdata_length).map(RData::CAA)?
            }
            RecordType::CNAME => {
                debug!("reading CNAME");
                RData::CNAME(try!(rdata::name::read(decoder)))
            }
            rt @ RecordType::IXFR => {
                return Err(ProtoErrorKind::UnknownRecordTypeValue(rt.into()).into())
            }
            RecordType::MX => {
                debug!("reading MX");
                RData::MX(try!(rdata::mx::read(decoder)))
            }
            RecordType::NULL => {
                debug!("reading NULL");
                RData::NULL(try!(rdata::null::read(decoder, rdata_length)))
            }
            RecordType::NS => {
                debug!("reading NS");
                RData::NS(try!(rdata::name::read(decoder)))
            }
            RecordType::OPT => {
                debug!("reading OPT");
                RData::OPT(try!(rdata::opt::read(decoder, rdata_length)))
            }
            RecordType::PTR => {
                debug!("reading PTR");
                RData::PTR(try!(rdata::name::read(decoder)))
            }
            RecordType::SOA => {
                debug!("reading SOA");
                RData::SOA(try!(rdata::soa::read(decoder)))
            }
            RecordType::SRV => {
                debug!("reading SRV");
                RData::SRV(try!(rdata::srv::read(decoder)))
            }
            RecordType::TXT => {
                debug!("reading TXT");
                RData::TXT(try!(rdata::txt::read(decoder, rdata_length)))
            }
            #[cfg(feature = "dnssec")]
            RecordType::DNSSEC(record_type) => {
                RData::DNSSEC(try!(DNSSECRData::read(decoder, record_type, rdata_length)))
            }
        };

        // we should have read rdata_length, but we did not
        let read = decoder.index() - start_idx;
        if read != rdata_length as usize {
            return Err(
                ProtoErrorKind::IncorrectRDataLengthRead(read, rdata_length as usize).into(),
            );
        }
        Ok(result)
    }

    /// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
    ///
    /// ```text
    /// 6.2.  Canonical RR Form
    ///
    ///    For the purposes of DNS security, the canonical form of an RR is the
    ///    wire format of the RR where:
    ///
    ///    ...
    ///
    ///    3.  if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
    ///        HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
    ///        SRV, DNAME, A6, RRSIG, or (rfc6840 removes NSEC), all uppercase
    ///        US-ASCII letters in the DNS names contained within the RDATA are replaced
    ///        by the corresponding lowercase US-ASCII letters;
    /// ```
    pub fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        match *self {
            RData::A(ref address) => rdata::a::emit(encoder, address),
            RData::AAAA(ref address) => rdata::aaaa::emit(encoder, address),
            RData::CAA(ref caa) => rdata::caa::emit(encoder, caa),
            // to_lowercase for rfc4034 and rfc6840
            RData::CNAME(ref name) => rdata::name::emit(encoder, name),
            // to_lowercase for rfc4034 and rfc6840
            RData::MX(ref mx) => rdata::mx::emit(encoder, mx),
            RData::NULL(ref null) => rdata::null::emit(encoder, null),
            // to_lowercase for rfc4034 and rfc6840
            RData::NS(ref name) => rdata::name::emit(encoder, name),
            RData::OPT(ref opt) => rdata::opt::emit(encoder, opt),
            // to_lowercase for rfc4034 and rfc6840
            RData::PTR(ref name) => rdata::name::emit(encoder, name),
            // to_lowercase for rfc4034 and rfc6840
            RData::SOA(ref soa) => rdata::soa::emit(encoder, soa),
            // to_lowercase for rfc4034 and rfc6840
            RData::SRV(ref srv) => rdata::srv::emit(encoder, srv),
            RData::TXT(ref txt) => rdata::txt::emit(encoder, txt),
            #[cfg(feature = "dnssec")]
            RData::DNSSEC(ref rdata) => rdata.emit(encoder),
        }
    }

    /// Converts this to a Recordtype
    pub fn to_record_type(&self) -> RecordType {
        match *self {
            RData::A(..) => RecordType::A,
            RData::AAAA(..) => RecordType::AAAA,
            RData::CAA(..) => RecordType::CAA,
            RData::CNAME(..) => RecordType::CNAME,
            RData::MX(..) => RecordType::MX,
            RData::NS(..) => RecordType::NS,
            RData::NULL(..) => RecordType::NULL,
            RData::OPT(..) => RecordType::OPT,
            RData::PTR(..) => RecordType::PTR,
            RData::SOA(..) => RecordType::SOA,
            RData::SRV(..) => RecordType::SRV,
            RData::TXT(..) => RecordType::TXT,
            #[cfg(feature = "dnssec")]
            RData::DNSSEC(ref rdata) =>
                RecordType::DNSSEC(DNSSECRData::to_record_type(rdata)),
        }
    }

    /// If this is an A or AAAA record type, then an IpAddr will be returned
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match *self {
            RData::A(a) => Some(IpAddr::from(a)),
            RData::AAAA(aaaa) => Some(IpAddr::from(aaaa)),
            _ => None,
        }
    }
}

impl PartialOrd<RData> for RData {
    fn partial_cmp(&self, other: &RData) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for RData {
    // RFC 4034                DNSSEC Resource Records               March 2005
    //
    // 6.3.  Canonical RR Ordering within an RRset
    //
    //    For the purposes of DNS security, RRs with the same owner name,
    //    class, and type are sorted by treating the RDATA portion of the
    //    canonical form of each RR as a left-justified unsigned octet sequence
    //    in which the absence of an octet sorts before a zero octet.
    //
    //    [RFC2181] specifies that an RRset is not allowed to contain duplicate
    //    records (multiple RRs with the same owner name, class, type, and
    //    RDATA).  Therefore, if an implementation detects duplicate RRs when
    //    putting the RRset in canonical form, it MUST treat this as a protocol
    //    error.  If the implementation chooses to handle this protocol error
    //    in the spirit of the robustness principle (being liberal in what it
    //    accepts), it MUST remove all but one of the duplicate RR(s) for the
    //    purposes of calculating the canonical form of the RRset.
    fn cmp(&self, other: &Self) -> Ordering {
        // TODO: how about we just store the bytes with the decoded data?
        //  the decoded data is useful for queries, the encoded data is needed for transfers, signing
        //  and ordering.
        self.to_bytes().cmp(&other.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;
    #[allow(unused)]
    use serialize::binary::*;
    use serialize::binary::bin_tests::test_emit_data_set;
    use rr::domain::Name;
    use rr::rdata::{MX, SOA, SRV, TXT};

    fn get_data() -> Vec<(RData, Vec<u8>)> {
        vec![
            (
                RData::CNAME(Name::from_labels(vec!["www", "example", "com"])),
                vec![
                    3,
                    b'w',
                    b'w',
                    b'w',
                    7,
                    b'e',
                    b'x',
                    b'a',
                    b'm',
                    b'p',
                    b'l',
                    b'e',
                    3,
                    b'c',
                    b'o',
                    b'm',
                    0,
                ]
            ),
            (
                RData::MX(MX::new(256, Name::from_labels(vec!["n"]))),
                vec![1, 0, 1, b'n', 0]
            ),
            (
                RData::NS(Name::from_labels(vec!["www", "example", "com"])),
                vec![
                    3,
                    b'w',
                    b'w',
                    b'w',
                    7,
                    b'e',
                    b'x',
                    b'a',
                    b'm',
                    b'p',
                    b'l',
                    b'e',
                    3,
                    b'c',
                    b'o',
                    b'm',
                    0,
                ]
            ),
            (
                RData::PTR(Name::from_labels(vec!["www", "example", "com"])),
                vec![
                    3,
                    b'w',
                    b'w',
                    b'w',
                    7,
                    b'e',
                    b'x',
                    b'a',
                    b'm',
                    b'p',
                    b'l',
                    b'e',
                    3,
                    b'c',
                    b'o',
                    b'm',
                    0,
                ]
            ),
            (
                RData::SOA(SOA::new(
                    Name::from_labels(vec!["www", "example", "com"]),
                    Name::from_labels(vec!["xxx", "example", "com"]),
                    u32::max_value(),
                    -1 as i32,
                    -1 as i32,
                    -1 as i32,
                    u32::max_value(),
                )),
                vec![
                    3,
                    b'w',
                    b'w',
                    b'w',
                    7,
                    b'e',
                    b'x',
                    b'a',
                    b'm',
                    b'p',
                    b'l',
                    b'e',
                    3,
                    b'c',
                    b'o',
                    b'm',
                    0,
                    3,
                    b'x',
                    b'x',
                    b'x',
                    0xC0,
                    0x04,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                ]
            ),
            (
                RData::TXT(TXT::new(vec![
                    "abcdef".to_string(),
                    "ghi".to_string(),
                    "".to_string(),
                    "j".to_string(),
                ])),
                vec![
                    6,
                    b'a',
                    b'b',
                    b'c',
                    b'd',
                    b'e',
                    b'f',
                    3,
                    b'g',
                    b'h',
                    b'i',
                    0,
                    1,
                    b'j',
                ]
            ),
            (
                RData::A(Ipv4Addr::from_str("0.0.0.0").unwrap()),
                vec![0, 0, 0, 0]
            ),
            (
                RData::AAAA(Ipv6Addr::from_str("::").unwrap()),
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            ),
            (
                RData::SRV(SRV::new(
                    1,
                    2,
                    3,
                    Name::from_labels(vec!["www", "example", "com"]),
                )),
                vec![
                    0x00,
                    0x01,
                    0x00,
                    0x02,
                    0x00,
                    0x03,
                    3,
                    b'w',
                    b'w',
                    b'w',
                    7,
                    b'e',
                    b'x',
                    b'a',
                    b'm',
                    b'p',
                    b'l',
                    b'e',
                    3,
                    b'c',
                    b'o',
                    b'm',
                    0,
                ]
            ),
        ]
    }

    // TODO this test kinda sucks, shows the problem with not storing the binary parts
    #[test]
    fn test_order() {
        let ordered: Vec<RData> =
            vec![
                RData::A(Ipv4Addr::from_str("0.0.0.0").unwrap()),
                RData::AAAA(Ipv6Addr::from_str("::").unwrap()),
                RData::SRV(SRV::new(
                    1,
                    2,
                    3,
                    Name::from_labels(vec!["www", "example", "com"]),
                )),
                RData::MX(MX::new(256, Name::from_labels(vec!["n"]))),
                RData::CNAME(Name::from_labels(vec!["www", "example", "com"])),
                RData::PTR(Name::from_labels(vec!["www", "example", "com"])),
                RData::NS(Name::from_labels(vec!["www", "example", "com"])),
                RData::SOA(SOA::new(
                    Name::from_labels(vec!["www", "example", "com"]),
                    Name::from_labels(vec!["xxx", "example", "com"]),
                    u32::max_value(),
                    -1 as i32,
                    -1 as i32,
                    -1 as i32,
                    u32::max_value(),
                )),
                RData::TXT(TXT::new(vec![
                    "abcdef".to_string(),
                    "ghi".to_string(),
                    "".to_string(),
                    "j".to_string(),
                ])),
            ];
        let mut unordered = vec![
            RData::CNAME(Name::from_labels(vec!["www", "example", "com"])),
            RData::MX(MX::new(256, Name::from_labels(vec!["n"]))),
            RData::PTR(Name::from_labels(vec!["www", "example", "com"])),
            RData::NS(Name::from_labels(vec!["www", "example", "com"])),
            RData::SOA(SOA::new(
                Name::from_labels(vec!["www", "example", "com"]),
                Name::from_labels(vec!["xxx", "example", "com"]),
                u32::max_value(),
                -1 as i32,
                -1 as i32,
                -1 as i32,
                u32::max_value(),
            )),
            RData::TXT(TXT::new(vec![
                "abcdef".to_string(),
                "ghi".to_string(),
                "".to_string(),
                "j".to_string(),
            ])),
            RData::A(Ipv4Addr::from_str("0.0.0.0").unwrap()),
            RData::AAAA(Ipv6Addr::from_str("::").unwrap()),
            RData::SRV(SRV::new(
                1,
                2,
                3,
                Name::from_labels(vec!["www", "example", "com"]),
            )),
        ];

        unordered.sort();
        assert_eq!(ordered, unordered);
    }

    #[test]
    fn test_read() {
        let mut test_pass = 0;
        for (expect, binary) in get_data() {
            test_pass += 1;
            println!("test {}: {:?}", test_pass, binary);
            let length = binary.len() as u16; // pre exclusive borrow
            let mut decoder = BinDecoder::new(&binary);

            assert_eq!(
                RData::read(
                    &mut decoder,
                    record_type_from_rdata(&expect),
                    length,
                ).unwrap(),
                expect
            );
        }
    }

    // TODO: this is kinda broken right now since it can't cover all types.
    fn record_type_from_rdata(rdata: &RData) -> ::rr::record_type::RecordType {
        match *rdata {
            RData::A(..) => RecordType::A,
            RData::AAAA(..) => RecordType::AAAA,
            RData::CAA(..) => RecordType::CAA,
            RData::CNAME(..) => RecordType::CNAME,
            RData::MX(..) => RecordType::MX,
            RData::NS(..) => RecordType::NS,
            RData::NULL(..) => RecordType::NULL,
            RData::OPT(..) => RecordType::OPT,
            RData::PTR(..) => RecordType::PTR,
            RData::SOA(..) => RecordType::SOA,
            RData::SRV(..) => RecordType::SRV,
            RData::TXT(..) => RecordType::TXT,
            #[cfg(feature = "dnssec")]
            RData::DNSSEC(ref rdata) => {
                use rr::dnssec::rdata::DNSSECRecordType;
                RecordType::DNSSEC(match *rdata {
                    DNSSECRData::DS(..) => DNSSECRecordType::DS,
                    DNSSECRData::KEY(..) => DNSSECRecordType::KEY,
                    DNSSECRData::DNSKEY(..) => DNSSECRecordType::DNSKEY,
                    DNSSECRData::NSEC(..) => DNSSECRecordType::NSEC,
                    DNSSECRData::NSEC3(..) => DNSSECRecordType::NSEC3,
                    DNSSECRData::NSEC3PARAM(..) => DNSSECRecordType::NSEC3PARAM,
                    DNSSECRData::SIG(..) => DNSSECRecordType::SIG,
                })
            }
        }
    }

    #[test]
    fn test_write_to() {
        test_emit_data_set(get_data(), |e, d| d.emit(e));
    }
}
