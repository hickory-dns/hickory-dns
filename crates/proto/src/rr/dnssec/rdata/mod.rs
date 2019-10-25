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

//! All record data structures and related serialization methods

// TODO: these should each be it's own struct, it would make parsing and decoding a little cleaner
//  and also a little more ergonomic when accessing.
// each of these module's has the parser for that rdata embedded, to keep the file sizes down...
pub mod dnskey;
pub mod ds;
pub mod key;
pub mod nsec;
pub mod nsec3;
pub mod nsec3param;
pub mod sig;

use std::str::FromStr;

use enum_as_inner::EnumAsInner;
use log::debug;

use crate::error::*;
use crate::rr::rdata::null;
use crate::rr::rdata::NULL;
use crate::serialize::binary::*;

pub use self::dnskey::DNSKEY;
pub use self::ds::DS;
pub use self::key::KEY;
pub use self::nsec::NSEC;
pub use self::nsec3::NSEC3;
pub use self::nsec3param::NSEC3PARAM;
pub use self::sig::SIG;

/// The type of the resource record, for DNSSEC-specific records.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum DNSSECRecordType {
    //  CDS,        //	59	RFC 7344	Child DS
    //  CDNSKEY,    //	60	RFC 7344	Child DNSKEY
    //  DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
    /// RFC 4034	DNS Key record: RSASHA256 and RSASHA512, RFC5702
    DNSKEY,
    /// RFC 4034	Delegation signer: RSASHA256 and RSASHA512, RFC5702
    DS,
    /// RFC 2535[3] and RFC 2930[4]	Key record
    KEY,
    /// RFC 4034	Next-Secure record
    NSEC,
    /// RFC 5155	NSEC record version 3
    NSEC3,
    /// RFC 5155	NSEC3 parameters
    NSEC3PARAM,
    /// RFC 4034	DNSSEC signature: RSASHA256 and RSASHA512, RFC5702
    RRSIG,
    /// RFC 2535 (2931)	Signature, to support 2137 Update.
    ///
    /// This isn't really a DNSSEC record type, but it is here because, at least
    /// for now, we enable/disable SIG(0) in exactly the same circumstances that
    /// we enable/disable DNSSEC. This may change in the future.
    SIG,
    /// Unknown or not yet supported DNSSec record type
    Unknown(u16),
}

impl FromStr for DNSSECRecordType {
    type Err = ProtoError;

    fn from_str(str: &str) -> ProtoResult<Self> {
        match str {
            "DNSKEY" => Ok(DNSSECRecordType::DNSKEY),
            "DS" => Ok(DNSSECRecordType::DS),
            "KEY" => Ok(DNSSECRecordType::KEY),
            "NSEC" => Ok(DNSSECRecordType::NSEC),
            "NSEC3" => Ok(DNSSECRecordType::NSEC3),
            "NSEC3PARAM" => Ok(DNSSECRecordType::NSEC3PARAM),
            "RRSIG" => Ok(DNSSECRecordType::RRSIG),
            "SIG" => Ok(DNSSECRecordType::SIG),
            _ => Err(ProtoErrorKind::UnknownRecordTypeStr(str.to_string()).into()),
        }
    }
}

impl From<u16> for DNSSECRecordType {
    fn from(value: u16) -> Self {
        match value {
            48 => DNSSECRecordType::DNSKEY,
            43 => DNSSECRecordType::DS,
            25 => DNSSECRecordType::KEY,
            47 => DNSSECRecordType::NSEC,
            50 => DNSSECRecordType::NSEC3,
            51 => DNSSECRecordType::NSEC3PARAM,
            46 => DNSSECRecordType::RRSIG,
            24 => DNSSECRecordType::SIG,
            _ => DNSSECRecordType::Unknown(value),
        }
    }
}

impl From<DNSSECRecordType> for &'static str {
    fn from(rt: DNSSECRecordType) -> &'static str {
        match rt {
            DNSSECRecordType::DNSKEY => "DNSKEY",
            DNSSECRecordType::DS => "DS",
            DNSSECRecordType::KEY => "KEY",
            DNSSECRecordType::NSEC => "NSEC",
            DNSSECRecordType::NSEC3 => "NSEC3",
            DNSSECRecordType::NSEC3PARAM => "NSEC3PARAM",
            DNSSECRecordType::RRSIG => "RRSIG",
            DNSSECRecordType::SIG => "SIG",
            DNSSECRecordType::Unknown(..) => "DnsSecUnknown",
        }
    }
}

impl From<DNSSECRecordType> for u16 {
    fn from(rt: DNSSECRecordType) -> Self {
        match rt {
            DNSSECRecordType::KEY => 25,
            DNSSECRecordType::DNSKEY => 48,
            DNSSECRecordType::DS => 43,
            DNSSECRecordType::NSEC => 47,
            DNSSECRecordType::NSEC3 => 50,
            DNSSECRecordType::NSEC3PARAM => 51,
            DNSSECRecordType::RRSIG => 46,
            DNSSECRecordType::SIG => 24,
            DNSSECRecordType::Unknown(value) => value,
        }
    }
}

/// Record data enum variants for DNSSEC-specific records.
#[derive(Debug, EnumAsInner, PartialEq, Clone, Eq)]
pub enum DNSSECRData {
    /// ```text
    /// RFC 4034                DNSSEC Resource Records               March 2005
    ///
    /// 2.1.  DNSKEY RDATA Wire Format
    ///
    ///    The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
    ///    octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
    ///    Field.
    ///
    ///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |              Flags            |    Protocol   |   Algorithm   |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    /                                                               /
    ///    /                            Public Key                         /
    ///    /                                                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// 2.1.1.  The Flags Field
    ///
    ///    Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
    ///    then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
    ///    owner name MUST be the name of a zone.  If bit 7 has value 0, then
    ///    the DNSKEY record holds some other type of DNS public key and MUST
    ///    NOT be used to verify RRSIGs that cover RRsets.
    ///
    ///    Bit 15 of the Flags field is the Secure Entry Point flag, described
    ///    in [RFC3757].  If bit 15 has value 1, then the DNSKEY record holds a
    ///    key intended for use as a secure entry point.  This flag is only
    ///    intended to be a hint to zone signing or debugging software as to the
    ///    intended use of this DNSKEY record; validators MUST NOT alter their
    ///    behavior during the signature validation process in any way based on
    ///    the setting of this bit.  This also means that a DNSKEY RR with the
    ///    SEP bit set would also need the Zone Key flag set in order to be able
    ///    to generate signatures legally.  A DNSKEY RR with the SEP set and the
    ///    Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
    ///    RRsets.
    ///
    ///    Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
    ///    creation of the DNSKEY RR and MUST be ignored upon receipt.
    ///
    /// RFC 5011                  Trust Anchor Update             September 2007
    ///
    /// 7.  IANA Considerations
    ///
    ///   The IANA has assigned a bit in the DNSKEY flags field (see Section 7
    ///   of [RFC4034]) for the REVOKE bit (8).
    /// ```
    DNSKEY(DNSKEY),

    /// ```text
    /// 5.1.  DS RDATA Wire Format
    ///
    /// The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
    ///           Algorithm field, a 1 octet Digest Type field, and a Digest field.
    ///
    ///                          1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     |           Key Tag             |  Algorithm    |  Digest Type  |
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     /                                                               /
    ///     /                            Digest                             /
    ///     /                                                               /
    ///     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    /// 5.1.1.  The Key Tag Field
    ///
    ///    The Key Tag field lists the key tag of the DNSKEY RR referred to by
    ///    the DS record, in network byte order.
    ///
    ///    The Key Tag used by the DS RR is identical to the Key Tag used by
    ///    RRSIG RRs.  Appendix B describes how to compute a Key Tag.
    ///
    /// 5.1.2.  The Algorithm Field
    ///
    ///    The Algorithm field lists the algorithm number of the DNSKEY RR
    ///    referred to by the DS record.
    ///
    ///    The algorithm number used by the DS RR is identical to the algorithm
    ///    number used by RRSIG and DNSKEY RRs.  Appendix A.1 lists the
    ///    algorithm number types.
    ///
    /// 5.1.3.  The Digest Type Field
    ///
    ///    The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
    ///    RR.  The Digest Type field identifies the algorithm used to construct
    ///    the digest.  Appendix A.2 lists the possible digest algorithm types.
    ///
    /// 5.1.4.  The Digest Field
    ///
    ///    The DS record refers to a DNSKEY RR by including a digest of that
    ///    DNSKEY RR.
    ///
    ///    The digest is calculated by concatenating the canonical form of the
    ///    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    ///    and then applying the digest algorithm.
    ///
    ///      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    ///
    ///       "|" denotes concatenation
    ///
    ///      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    ///
    ///    The size of the digest may vary depending on the digest algorithm and
    ///    DNSKEY RR size.  As of the time of this writing, the only defined
    ///    digest algorithm is SHA-1, which produces a 20 octet digest.
    /// ```
    DS(DS),

    /// ```text
    /// RFC 2535                DNS Security Extensions               March 1999
    ///
    /// 3.1 KEY RDATA format
    ///
    ///  The RDATA for a KEY RR consists of flags, a protocol octet, the
    ///  algorithm number octet, and the public key itself.  The format is as
    ///  follows:
    ///
    ///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |             flags             |    protocol   |   algorithm   |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                                                               /
    ///  /                          public key                           /
    ///  /                                                               /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    ///
    ///  The KEY RR is not intended for storage of certificates and a separate
    ///  certificate RR has been developed for that purpose, defined in [RFC
    ///  2538].
    ///
    ///  The meaning of the KEY RR owner name, flags, and protocol octet are
    ///  described in Sections 3.1.1 through 3.1.5 below.  The flags and
    ///  algorithm must be examined before any data following the algorithm
    ///  octet as they control the existence and format of any following data.
    ///  The algorithm and public key fields are described in Section 3.2.
    ///  The format of the public key is algorithm dependent.
    ///
    ///  KEY RRs do not specify their validity period but their authenticating
    ///  SIG RR(s) do as described in Section 4 below.
    /// ```
    KEY(KEY),

    /// ```text
    /// RFC 4034                DNSSEC Resource Records               March 2005
    ///
    /// 4.1.  NSEC RDATA Wire Format
    ///
    ///  The RDATA of the NSEC RR is as shown below:
    ///
    ///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  /                      Next Domain Name                         /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  /                       Type Bit Maps                           /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    NSEC(NSEC),

    /// ```text
    /// RFC 5155                         NSEC3                        March 2008
    ///
    /// 3.2.  NSEC3 RDATA Wire Format
    ///
    ///  The RDATA of the NSEC3 RR is as shown below:
    ///
    ///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |   Hash Alg.   |     Flags     |          Iterations           |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |  Salt Length  |                     Salt                      /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |  Hash Length  |             Next Hashed Owner Name            /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  /                         Type Bit Maps                         /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///  Hash Algorithm is a single octet.
    ///
    ///  Flags field is a single octet, the Opt-Out flag is the least
    ///  significant bit, as shown below:
    ///
    ///   0 1 2 3 4 5 6 7
    ///  +-+-+-+-+-+-+-+-+
    ///  |             |O|
    ///  +-+-+-+-+-+-+-+-+
    ///
    ///  Iterations is represented as a 16-bit unsigned integer, with the most
    ///  significant bit first.
    ///
    ///  Salt Length is represented as an unsigned octet.  Salt Length
    ///  represents the length of the Salt field in octets.  If the value is
    ///  zero, the following Salt field is omitted.
    ///
    ///  Salt, if present, is encoded as a sequence of binary octets.  The
    ///  length of this field is determined by the preceding Salt Length
    ///  field.
    ///
    ///  Hash Length is represented as an unsigned octet.  Hash Length
    ///  represents the length of the Next Hashed Owner Name field in octets.
    ///
    ///  The next hashed owner name is not base32 encoded, unlike the owner
    ///  name of the NSEC3 RR.  It is the unmodified binary hash value.  It
    ///  does not include the name of the containing zone.  The length of this
    ///  field is determined by the preceding Hash Length field.
    ///
    /// 3.2.1.  Type Bit Maps Encoding
    ///
    ///  The encoding of the Type Bit Maps field is the same as that used by
    ///  the NSEC RR, described in [RFC4034].  It is explained and clarified
    ///  here for clarity.
    ///
    ///  The RR type space is split into 256 window blocks, each representing
    ///  the low-order 8 bits of the 16-bit RR type space.  Each block that
    ///  has at least one active RR type is encoded using a single octet
    ///  window number (from 0 to 255), a single octet bitmap length (from 1
    ///  to 32) indicating the number of octets used for the bitmap of the
    ///  window block, and up to 32 octets (256 bits) of bitmap.
    ///
    ///  Blocks are present in the NSEC3 RR RDATA in increasing numerical
    ///  order.
    ///
    ///     Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+
    ///
    ///     where "|" denotes concatenation.
    ///
    ///  Each bitmap encodes the low-order 8 bits of RR types within the
    ///  window block, in network bit order.  The first bit is bit 0.  For
    ///  window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
    ///  to RR type 2 (NS), and so forth.  For window block 1, bit 1
    ///  corresponds to RR type 257, bit 2 to RR type 258.  If a bit is set to
    ///  1, it indicates that an RRSet of that type is present for the
    ///  original owner name of the NSEC3 RR.  If a bit is set to 0, it
    ///  indicates that no RRSet of that type is present for the original
    ///  owner name of the NSEC3 RR.
    ///
    ///  Since bit 0 in window block 0 refers to the non-existing RR type 0,
    ///  it MUST be set to 0.  After verification, the validator MUST ignore
    ///  the value of bit 0 in window block 0.
    ///
    ///  Bits representing Meta-TYPEs or QTYPEs as specified in Section 3.1 of
    ///  [RFC2929] or within the range reserved for assignment only to QTYPEs
    ///  and Meta-TYPEs MUST be set to 0, since they do not appear in zone
    ///  data.  If encountered, they must be ignored upon reading.
    ///
    ///  Blocks with no types present MUST NOT be included.  Trailing zero
    ///  octets in the bitmap MUST be omitted.  The length of the bitmap of
    ///  each block is determined by the type code with the largest numerical
    ///  value, within that block, among the set of RR types present at the
    ///  original owner name of the NSEC3 RR.  Trailing octets not specified
    ///  MUST be interpreted as zero octets.
    /// ```
    NSEC3(NSEC3),

    /// ```text
    /// RFC 5155                         NSEC3                        March 2008
    ///
    /// 4.2.  NSEC3PARAM RDATA Wire Format
    ///
    ///  The RDATA of the NSEC3PARAM RR is as shown below:
    ///
    ///                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |   Hash Alg.   |     Flags     |          Iterations           |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |  Salt Length  |                     Salt                      /
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///  Hash Algorithm is a single octet.
    ///
    ///  Flags field is a single octet.
    ///
    ///  Iterations is represented as a 16-bit unsigned integer, with the most
    ///  significant bit first.
    ///
    ///  Salt Length is represented as an unsigned octet.  Salt Length
    ///  represents the length of the following Salt field in octets.  If the
    ///  value is zero, the Salt field is omitted.
    ///
    ///  Salt, if present, is encoded as a sequence of binary octets.  The
    ///  length of this field is determined by the preceding Salt Length
    ///  field.
    /// ```
    NSEC3PARAM(NSEC3PARAM),

    /// ```text
    /// RFC 2535 & 2931   DNS Security Extensions               March 1999
    /// RFC 4034          DNSSEC Resource Records               March 2005
    ///
    /// 3.1.  RRSIG RDATA Wire Format
    ///
    ///    The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
    ///    1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
    ///    TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
    ///    Inception field, a 2 octet Key tag, the Signer's Name field, and the
    ///    Signature field.
    ///
    ///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |        Type Covered           |  Algorithm    |     Labels    |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |                         Original TTL                          |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |                      Signature Expiration                     |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |                      Signature Inception                      |
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    |            Key Tag            |                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
    ///    /                                                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    /                                                               /
    ///    /                            Signature                          /
    ///    /                                                               /
    ///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    SIG(SIG),

    /// Unknown or unsupported DNSSec record data
    Unknown {
        /// RecordType code
        code: u16,
        /// RData associated to the record
        rdata: NULL,
    },
}

impl DNSSECRData {
    pub(crate) fn read(
        decoder: &mut BinDecoder,
        record_type: DNSSECRecordType,
        rdata_length: Restrict<u16>,
    ) -> ProtoResult<Self> {
        match record_type {
            DNSSECRecordType::DNSKEY => {
                debug!("reading DNSKEY");
                dnskey::read(decoder, rdata_length).map(DNSSECRData::DNSKEY)
            }
            DNSSECRecordType::DS => {
                debug!("reading DS");
                ds::read(decoder, rdata_length).map(DNSSECRData::DS)
            }
            DNSSECRecordType::KEY => {
                debug!("reading KEY");
                key::read(decoder, rdata_length).map(DNSSECRData::KEY)
            }
            DNSSECRecordType::NSEC => {
                debug!("reading NSEC");
                nsec::read(decoder, rdata_length).map(DNSSECRData::NSEC)
            }
            DNSSECRecordType::NSEC3 => {
                debug!("reading NSEC3");
                nsec3::read(decoder, rdata_length).map(DNSSECRData::NSEC3)
            }
            DNSSECRecordType::NSEC3PARAM => {
                debug!("reading NSEC3PARAM");
                nsec3param::read(decoder).map(DNSSECRData::NSEC3PARAM)
            }
            DNSSECRecordType::RRSIG => {
                debug!("reading RRSIG");
                sig::read(decoder, rdata_length).map(DNSSECRData::SIG)
            }
            DNSSECRecordType::SIG => {
                debug!("reading SIG");
                sig::read(decoder, rdata_length).map(DNSSECRData::SIG)
            }
            DNSSECRecordType::Unknown(code) => {
                debug!("reading unknown dnssec: {}", code);
                null::read(decoder, rdata_length).map(|rdata| DNSSECRData::Unknown { code, rdata })
            }
        }
    }

    pub(crate) fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        match *self {
            DNSSECRData::DS(ref ds) => {
                encoder.with_canonical_names(|encoder| ds::emit(encoder, ds))
            }
            DNSSECRData::KEY(ref key) => {
                encoder.with_canonical_names(|encoder| key::emit(encoder, key))
            }
            DNSSECRData::DNSKEY(ref dnskey) => {
                encoder.with_canonical_names(|encoder| dnskey::emit(encoder, dnskey))
            }
            DNSSECRData::NSEC(ref nsec) => {
                encoder.with_canonical_names(|encoder| nsec::emit(encoder, nsec))
            }
            DNSSECRData::NSEC3(ref nsec3) => {
                encoder.with_canonical_names(|encoder| nsec3::emit(encoder, nsec3))
            }
            DNSSECRData::NSEC3PARAM(ref nsec3param) => {
                encoder.with_canonical_names(|encoder| nsec3param::emit(encoder, nsec3param))
            }
            DNSSECRData::SIG(ref sig) => {
                encoder.with_canonical_names(|encoder| sig::emit(encoder, sig))
            }
            DNSSECRData::Unknown { ref rdata, .. } => {
                encoder.with_canonical_names(|encoder| null::emit(encoder, rdata))
            }
        }
    }

    pub(crate) fn to_record_type(&self) -> DNSSECRecordType {
        match *self {
            DNSSECRData::DS(..) => DNSSECRecordType::DS,
            DNSSECRData::KEY(..) => DNSSECRecordType::KEY,
            DNSSECRData::DNSKEY(..) => DNSSECRecordType::DNSKEY,
            DNSSECRData::NSEC(..) => DNSSECRecordType::NSEC,
            DNSSECRData::NSEC3(..) => DNSSECRecordType::NSEC3,
            DNSSECRData::NSEC3PARAM(..) => DNSSECRecordType::NSEC3PARAM,
            DNSSECRData::SIG(..) => DNSSECRecordType::SIG,
            DNSSECRData::Unknown { code, .. } => DNSSECRecordType::Unknown(code),
        }
    }
}
