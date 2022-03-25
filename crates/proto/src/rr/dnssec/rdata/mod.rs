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

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

// TODO: these should each be it's own struct, it would make parsing and decoding a little cleaner
//  and also a little more ergonomic when accessing.
// each of these module's has the parser for that rdata embedded, to keep the file sizes down...
pub mod dnskey;
pub mod ds;
#[allow(deprecated)]
pub mod key;
pub mod nsec;
pub mod nsec3;
pub mod nsec3param;
pub mod sig;
pub mod tsig;

use enum_as_inner::EnumAsInner;
use tracing::trace;

use crate::error::*;
use crate::rr::rdata::null;
use crate::rr::rdata::NULL;
use crate::rr::{RData, RecordType};
use crate::serialize::binary::*;

pub use self::dnskey::DNSKEY;
pub use self::ds::DS;
pub use self::key::KEY;
pub use self::nsec::NSEC;
pub use self::nsec3::NSEC3;
pub use self::nsec3param::NSEC3PARAM;
pub use self::sig::SIG;
pub use self::tsig::TSIG;

/// The type of the resource record, for DNSSEC-specific records.
#[deprecated(note = "All RecordType definitions have been moved into RecordType")]
pub type DNSSECRecordType = RecordType;

/// Record data enum variants for DNSSEC-specific records.
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, EnumAsInner, PartialEq, Clone, Eq)]
#[non_exhaustive]
pub enum DNSSECRData {
    /// ```text
    /// RFC 7344              Delegation Trust Maintenance        September 2014
    ///
    /// 3.2.  CDNSKEY Resource Record Format
    ///
    ///    The wire and presentation format of the CDNSKEY ("Child DNSKEY")
    ///    resource record is identical to the DNSKEY record.  IANA has
    ///    allocated RR code 60 for the CDNSKEY resource record via Expert
    ///    Review.  The CDNSKEY RR uses the same registries as DNSKEY for its
    ///    fields.
    ///
    ///    No special processing is performed by authoritative servers or by
    ///    resolvers, when serving or resolving.  For all practical purposes,
    ///    CDNSKEY is a regular RR type.
    /// ```
    CDNSKEY(DNSKEY),

    /// ```text
    /// RFC 7344              Delegation Trust Maintenance        September 2014
    ///
    /// 3.1.  CDS Resource Record Format
    ///    The wire and presentation format of the Child DS (CDS) resource
    ///    record is identical to the DS record [RFC4034].  IANA has allocated
    ///    RR code 59 for the CDS resource record via Expert Review
    ///    [DNS-TRANSPORT].  The CDS RR uses the same registries as DS for its
    ///    fields.
    ///
    ///    No special processing is performed by authoritative servers or by
    ///    resolvers, when serving or resolving.  For all practical purposes,
    ///    CDS is a regular RR type.
    /// ```
    CDS(DS),

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

    /// [RFC 8945, Secret Key Transaction Authentication for DNS](https://tools.ietf.org/html/rfc8945#section-4.2)
    ///
    /// ```text
    /// 4.2.  TSIG Record Format
    ///
    ///   The fields of the TSIG RR are described below.  All multi-octet
    ///   integers in the record are sent in network byte order (see
    ///   Section 2.3.2 of [RFC1035]).
    ///
    ///   NAME:  The name of the key used, in domain name syntax.  The name
    ///      should reflect the names of the hosts and uniquely identify the
    ///      key among a set of keys these two hosts may share at any given
    ///      time.  For example, if hosts A.site.example and B.example.net
    ///      share a key, possibilities for the key name include
    ///      <id>.A.site.example, <id>.B.example.net, and
    ///      <id>.A.site.example.B.example.net.  It should be possible for more
    ///      than one key to be in simultaneous use among a set of interacting
    ///      hosts.  This allows for periodic key rotation as per best
    ///      operational practices, as well as algorithm agility as indicated
    ///      by [RFC7696].
    ///
    ///      The name may be used as a local index to the key involved, but it
    ///      is recommended that it be globally unique.  Where a key is just
    ///      shared between two hosts, its name actually need only be
    ///      meaningful to them, but it is recommended that the key name be
    ///      mnemonic and incorporate the names of participating agents or
    ///      resources as suggested above.
    ///
    ///   TYPE:  This MUST be TSIG (250: Transaction SIGnature).
    ///
    ///   CLASS:  This MUST be ANY.
    ///
    ///   TTL:  This MUST be 0.
    ///
    ///   RDLENGTH:  (variable)
    ///
    ///   RDATA:  The RDATA for a TSIG RR consists of a number of fields,
    ///      described below:
    ///
    ///                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    ///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       /                         Algorithm Name                        /
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |                                                               |
    ///       |          Time Signed          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |                               |            Fudge              |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |          MAC Size             |                               /
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+             MAC               /
    ///       /                                                               /
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |          Original ID          |            Error              |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///       |          Other Len            |                               /
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           Other Data          /
    ///       /                                                               /
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    ///   The contents of the RDATA fields are:
    ///
    ///   Algorithm Name:
    ///      an octet sequence identifying the TSIG algorithm in the domain
    ///      name syntax.  (Allowed names are listed in Table 3.)  The name is
    ///      stored in the DNS name wire format as described in [RFC1034].  As
    ///      per [RFC3597], this name MUST NOT be compressed.
    ///
    ///   Time Signed:
    ///      an unsigned 48-bit integer containing the time the message was
    ///      signed as seconds since 00:00 on 1970-01-01 UTC, ignoring leap
    ///      seconds.
    ///
    ///   Fudge:
    ///      an unsigned 16-bit integer specifying the allowed time difference
    ///      in seconds permitted in the Time Signed field.
    ///
    ///   MAC Size:
    ///      an unsigned 16-bit integer giving the length of the MAC field in
    ///      octets.  Truncation is indicated by a MAC Size less than the size
    ///      of the keyed hash produced by the algorithm specified by the
    ///      Algorithm Name.
    ///
    ///   MAC:
    ///      a sequence of octets whose contents are defined by the TSIG
    ///      algorithm used, possibly truncated as specified by the MAC Size.
    ///      The length of this field is given by the MAC Size.  Calculation of
    ///      the MAC is detailed in Section 4.3.
    ///
    ///   Original ID:
    ///      an unsigned 16-bit integer holding the message ID of the original
    ///      request message.  For a TSIG RR on a request, it is set equal to
    ///      the DNS message ID.  In a TSIG attached to a response -- or in
    ///      cases such as the forwarding of a dynamic update request -- the
    ///      field contains the ID of the original DNS request.
    ///
    ///   Error:
    ///      in responses, an unsigned 16-bit integer containing the extended
    ///      RCODE covering TSIG processing.  In requests, this MUST be zero.
    ///
    ///   Other Len:
    ///      an unsigned 16-bit integer specifying the length of the Other Data
    ///      field in octets.
    ///
    ///   Other Data:
    ///      additional data relevant to the TSIG record.  In responses, this
    ///      will be empty (i.e., Other Len will be zero) unless the content of
    ///      the Error field is BADTIME, in which case it will be a 48-bit
    ///      unsigned integer containing the server's current time as the
    ///      number of seconds since 00:00 on 1970-01-01 UTC, ignoring leap
    ///      seconds (see Section 5.2.3).  This document assigns no meaning to
    ///      its contents in requests.
    /// ```
    TSIG(TSIG),

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
        decoder: &mut BinDecoder<'_>,
        record_type: RecordType,
        rdata_length: Restrict<u16>,
    ) -> ProtoResult<Self> {
        match record_type {
            RecordType::CDNSKEY => {
                trace!("reading CDNSKEY");
                dnskey::read(decoder, rdata_length).map(Self::CDNSKEY)
            }
            RecordType::CDS => {
                trace!("reading CDS");
                ds::read(decoder, rdata_length).map(Self::CDS)
            }
            RecordType::DNSKEY => {
                trace!("reading DNSKEY");
                dnskey::read(decoder, rdata_length).map(Self::DNSKEY)
            }
            RecordType::DS => {
                trace!("reading DS");
                ds::read(decoder, rdata_length).map(Self::DS)
            }
            RecordType::KEY => {
                trace!("reading KEY");
                key::read(decoder, rdata_length).map(Self::KEY)
            }
            RecordType::NSEC => {
                trace!("reading NSEC");
                nsec::read(decoder, rdata_length).map(Self::NSEC)
            }
            RecordType::NSEC3 => {
                trace!("reading NSEC3");
                nsec3::read(decoder, rdata_length).map(Self::NSEC3)
            }
            RecordType::NSEC3PARAM => {
                trace!("reading NSEC3PARAM");
                nsec3param::read(decoder).map(Self::NSEC3PARAM)
            }
            RecordType::RRSIG => {
                trace!("reading RRSIG");
                sig::read(decoder, rdata_length).map(Self::SIG)
            }
            RecordType::SIG => {
                trace!("reading SIG");
                sig::read(decoder, rdata_length).map(Self::SIG)
            }
            RecordType::TSIG => {
                trace!("reading TSIG");
                tsig::read(decoder, rdata_length).map(Self::TSIG)
            }
            r => {
                panic!("not a dnssec RecordType: {}", r);
            }
        }
    }

    pub(crate) fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        match *self {
            Self::CDNSKEY(ref cdnskey) => {
                encoder.with_canonical_names(|encoder| dnskey::emit(encoder, cdnskey))
            }
            Self::CDS(ref cds) => encoder.with_canonical_names(|encoder| ds::emit(encoder, cds)),
            Self::DS(ref ds) => encoder.with_canonical_names(|encoder| ds::emit(encoder, ds)),
            Self::KEY(ref key) => encoder.with_canonical_names(|encoder| key::emit(encoder, key)),
            Self::DNSKEY(ref dnskey) => {
                encoder.with_canonical_names(|encoder| dnskey::emit(encoder, dnskey))
            }
            Self::NSEC(ref nsec) => {
                encoder.with_canonical_names(|encoder| nsec::emit(encoder, nsec))
            }
            Self::NSEC3(ref nsec3) => {
                encoder.with_canonical_names(|encoder| nsec3::emit(encoder, nsec3))
            }
            Self::NSEC3PARAM(ref nsec3param) => {
                encoder.with_canonical_names(|encoder| nsec3param::emit(encoder, nsec3param))
            }
            Self::SIG(ref sig) => encoder.with_canonical_names(|encoder| sig::emit(encoder, sig)),
            Self::TSIG(ref tsig) => tsig::emit(encoder, tsig),
            Self::Unknown { ref rdata, .. } => {
                encoder.with_canonical_names(|encoder| null::emit(encoder, rdata))
            }
        }
    }

    pub(crate) fn to_record_type(&self) -> RecordType {
        match *self {
            Self::CDNSKEY(..) => RecordType::CDNSKEY,
            Self::CDS(..) => RecordType::CDS,
            Self::DS(..) => RecordType::DS,
            Self::KEY(..) => RecordType::KEY,
            Self::DNSKEY(..) => RecordType::DNSKEY,
            Self::NSEC(..) => RecordType::NSEC,
            Self::NSEC3(..) => RecordType::NSEC3,
            Self::NSEC3PARAM(..) => RecordType::NSEC3PARAM,
            Self::SIG(..) => RecordType::SIG,
            Self::TSIG(..) => RecordType::TSIG,
            Self::Unknown { code, .. } => RecordType::Unknown(code),
        }
    }
}

impl fmt::Display for DNSSECRData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fn w<D: fmt::Display>(f: &mut fmt::Formatter<'_>, d: D) -> Result<(), fmt::Error> {
            write!(f, "{rdata}", rdata = d)
        }

        match self {
            Self::CDNSKEY(key) => w(f, key),
            Self::CDS(ds) => w(f, ds),
            Self::DS(ds) => w(f, ds),
            Self::KEY(key) => w(f, key),
            Self::DNSKEY(key) => w(f, key),
            Self::NSEC(nsec) => w(f, nsec),
            Self::NSEC3(nsec3) => w(f, nsec3),
            Self::NSEC3PARAM(nsec3param) => w(f, nsec3param),
            Self::SIG(sig) => w(f, sig),
            Self::TSIG(ref tsig) => w(f, tsig),
            Self::Unknown { rdata, .. } => w(f, rdata),
        }
    }
}

impl From<DNSSECRData> for RData {
    fn from(rdata: DNSSECRData) -> Self {
        Self::DNSSEC(rdata)
    }
}
