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

use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::convert::From;
use std::cmp::Ordering;

use ::error::*;
use ::serialize::binary::*;
use ::serialize::txt::*;
use super::domain::Name;
use super::record_type::RecordType;
use super::rdata;
use super::rdata::{ DNSKEY, DS, MX, NSEC, NSEC3, NSEC3PARAM, NULL, OPT, SIG, SOA, SRV, TXT };

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
  //-- RFC 1035 -- Domain Implementation and Specification    November 1987
  //
  // 3.4. Internet specific RRs
  //
  // 3.4.1. A RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    ADDRESS                    |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // ADDRESS         A 32 bit Internet address.
  //
  // Hosts that have multiple Internet addresses will have multiple A
  // records.
  //
  // A records cause no additional section processing.  The RDATA section of
  // an A line in a master file is an Internet address expressed as four
  // decimal numbers separated by dots without any imbedded spaces (e.g.,
  // "10.2.0.52" or "192.0.5.6").
  A(Ipv4Addr),

  //-- RFC 1886 -- IPv6 DNS Extensions              December 1995
  //
  // 2.2 AAAA data format
  //
  //    A 128 bit IPv6 address is encoded in the data portion of an AAAA
  //    resource record in network byte order (high-order byte first).
  AAAA(Ipv6Addr),


  //   3.3. Standard RRs
  //
  // The following RR definitions are expected to occur, at least
  // potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
  // will be used in all classes, and have the same format in all classes.
  // Because their RDATA format is known, all domain names in the RDATA
  // section of these RRs may be compressed.
  //
  // <domain-name> is a domain name represented as a series of labels, and
  // terminated by a label with zero length.  <character-string> is a single
  // length octet followed by that number of characters.  <character-string>
  // is treated as binary information, and can be up to 256 characters in
  // length (including the length octet).
  //
  // 3.3.1. CNAME RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                     CNAME                     /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // CNAME           A <domain-name> which specifies the canonical or primary
  //                 name for the owner.  The owner name is an alias.
  //
  // CNAME RRs cause no additional section processing, but name servers may
  // choose to restart the query at the canonical name in certain cases.  See
  // the description of name server logic in [RFC-1034] for details.
  CNAME(Name),

  // RFC 4034                DNSSEC Resource Records               March 2005
  //
  // 2.1.  DNSKEY RDATA Wire Format
  //
  //    The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
  //    octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
  //    Field.
  //
  //                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |              Flags            |    Protocol   |   Algorithm   |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    /                                                               /
  //    /                            Public Key                         /
  //    /                                                               /
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  // 2.1.1.  The Flags Field
  //
  //    Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
  //    then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
  //    owner name MUST be the name of a zone.  If bit 7 has value 0, then
  //    the DNSKEY record holds some other type of DNS public key and MUST
  //    NOT be used to verify RRSIGs that cover RRsets.
  //
  //    Bit 15 of the Flags field is the Secure Entry Point flag, described
  //    in [RFC3757].  If bit 15 has value 1, then the DNSKEY record holds a
  //    key intended for use as a secure entry point.  This flag is only
  //    intended to be a hint to zone signing or debugging software as to the
  //    intended use of this DNSKEY record; validators MUST NOT alter their
  //    behavior during the signature validation process in any way based on
  //    the setting of this bit.  This also means that a DNSKEY RR with the
  //    SEP bit set would also need the Zone Key flag set in order to be able
  //    to generate signatures legally.  A DNSKEY RR with the SEP set and the
  //    Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
  //    RRsets.
  //
  //    Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
  //    creation of the DNSKEY RR and MUST be ignored upon receipt.
  //
  // RFC 5011                  Trust Anchor Update             September 2007
  //
  // 7.  IANA Considerations
  //
  //   The IANA has assigned a bit in the DNSKEY flags field (see Section 7
  //   of [RFC4034]) for the REVOKE bit (8).
  DNSKEY(DNSKEY),


  // 5.1.  DS RDATA Wire Format
  //
  // The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
  //           Algorithm field, a 1 octet Digest Type field, and a Digest field.
  //
  //                          1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //     |           Key Tag             |  Algorithm    |  Digest Type  |
  //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //     /                                                               /
  //     /                            Digest                             /
  //     /                                                               /
  //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  // 5.1.1.  The Key Tag Field
  //
  //    The Key Tag field lists the key tag of the DNSKEY RR referred to by
  //    the DS record, in network byte order.
  //
  //    The Key Tag used by the DS RR is identical to the Key Tag used by
  //    RRSIG RRs.  Appendix B describes how to compute a Key Tag.
  //
  // 5.1.2.  The Algorithm Field
  //
  //    The Algorithm field lists the algorithm number of the DNSKEY RR
  //    referred to by the DS record.
  //
  //    The algorithm number used by the DS RR is identical to the algorithm
  //    number used by RRSIG and DNSKEY RRs.  Appendix A.1 lists the
  //    algorithm number types.
  //
  // 5.1.3.  The Digest Type Field
  //
  //    The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
  //    RR.  The Digest Type field identifies the algorithm used to construct
  //    the digest.  Appendix A.2 lists the possible digest algorithm types.
  //
  // 5.1.4.  The Digest Field
  //
  //    The DS record refers to a DNSKEY RR by including a digest of that
  //    DNSKEY RR.
  //
  //    The digest is calculated by concatenating the canonical form of the
  //    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
  //    and then applying the digest algorithm.
  //
  //      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
  //
  //       "|" denotes concatenation
  //
  //      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
  //
  //    The size of the digest may vary depending on the digest algorithm and
  //    DNSKEY RR size.  As of the time of this writing, the only defined
  //    digest algorithm is SHA-1, which produces a 20 octet digest.
  DS(DS),

  // RFC 2535                DNS Security Extensions               March 1999
  //
  // 3.1 KEY RDATA format
  //
  //  The RDATA for a KEY RR consists of flags, a protocol octet, the
  //  algorithm number octet, and the public key itself.  The format is as
  //  follows:
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |             flags             |    protocol   |   algorithm   |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                                                               /
  //  /                          public key                           /
  //  /                                                               /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
  //
  //  The KEY RR is not intended for storage of certificates and a separate
  //  certificate RR has been developed for that purpose, defined in [RFC
  //  2538].
  //
  //  The meaning of the KEY RR owner name, flags, and protocol octet are
  //  described in Sections 3.1.1 through 3.1.5 below.  The flags and
  //  algorithm must be examined before any data following the algorithm
  //  octet as they control the existence and format of any following data.
  //  The algorithm and public key fields are described in Section 3.2.
  //  The format of the public key is algorithm dependent.
  //
  //  KEY RRs do not specify their validity period but their authenticating
  //  SIG RR(s) do as described in Section 4 below.
  KEY(DNSKEY),

  // 3.3.9. MX RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                  PREFERENCE                   |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   EXCHANGE                    /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // PREFERENCE      A 16 bit integer which specifies the preference given to
  //                 this RR among others at the same owner.  Lower values
  //                 are preferred.
  //
  // EXCHANGE        A <domain-name> which specifies a host willing to act as
  //                 a mail exchange for the owner name.
  //
  // MX records cause type A additional section processing for the host
  // specified by EXCHANGE.  The use of MX RRs is explained in detail in
  // [RFC-974].
  MX(MX),

  // 3.3.10. NULL RDATA format (EXPERIMENTAL)
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                  <anything>                   /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // Anything at all may be in the RDATA field so long as it is 65535 octets
  // or less.
  //
  // NULL records cause no additional section processing.  NULL RRs are not
  // allowed in master files.  NULLs are used as placeholders in some
  // experimental extensions of the DNS.
  NULL(NULL),

  // 3.3.11. NS RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   NSDNAME                     /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // NSDNAME         A <domain-name> which specifies a host which should be
  //                 authoritative for the specified class and domain.
  //
  // NS records cause both the usual additional section processing to locate
  // a type A record, and, when used in a referral, a special search of the
  // zone in which they reside for glue information.
  //
  // The NS RR states that the named host should be expected to have a zone
  // starting at owner name of the specified class.  Note that the class may
  // not indicate the protocol family which should be used to communicate
  // with the host, although it is typically a strong hint.  For example,
  // hosts which are name servers for either Internet (IN) or Hesiod (HS)
  // class information are normally queried using IN class protocols.
  NS(Name),

  // RFC 4034                DNSSEC Resource Records               March 2005
  //
  // 4.1.  NSEC RDATA Wire Format
  //
  //  The RDATA of the NSEC RR is as shown below:
  //
  //                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  /                      Next Domain Name                         /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  /                       Type Bit Maps                           /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  NSEC(NSEC),

  // RFC 5155                         NSEC3                        March 2008
  //
  // 3.2.  NSEC3 RDATA Wire Format
  //
  //  The RDATA of the NSEC3 RR is as shown below:
  //
  //                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |   Hash Alg.   |     Flags     |          Iterations           |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |  Salt Length  |                     Salt                      /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |  Hash Length  |             Next Hashed Owner Name            /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  /                         Type Bit Maps                         /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //  Hash Algorithm is a single octet.
  //
  //  Flags field is a single octet, the Opt-Out flag is the least
  //  significant bit, as shown below:
  //
  //   0 1 2 3 4 5 6 7
  //  +-+-+-+-+-+-+-+-+
  //  |             |O|
  //  +-+-+-+-+-+-+-+-+
  //
  //  Iterations is represented as a 16-bit unsigned integer, with the most
  //  significant bit first.
  //
  //  Salt Length is represented as an unsigned octet.  Salt Length
  //  represents the length of the Salt field in octets.  If the value is
  //  zero, the following Salt field is omitted.
  //
  //  Salt, if present, is encoded as a sequence of binary octets.  The
  //  length of this field is determined by the preceding Salt Length
  //  field.
  //
  //  Hash Length is represented as an unsigned octet.  Hash Length
  //  represents the length of the Next Hashed Owner Name field in octets.
  //
  //  The next hashed owner name is not base32 encoded, unlike the owner
  //  name of the NSEC3 RR.  It is the unmodified binary hash value.  It
  //  does not include the name of the containing zone.  The length of this
  //  field is determined by the preceding Hash Length field.
  //
  // 3.2.1.  Type Bit Maps Encoding
  //
  //  The encoding of the Type Bit Maps field is the same as that used by
  //  the NSEC RR, described in [RFC4034].  It is explained and clarified
  //  here for clarity.
  //
  //  The RR type space is split into 256 window blocks, each representing
  //  the low-order 8 bits of the 16-bit RR type space.  Each block that
  //  has at least one active RR type is encoded using a single octet
  //  window number (from 0 to 255), a single octet bitmap length (from 1
  //  to 32) indicating the number of octets used for the bitmap of the
  //  window block, and up to 32 octets (256 bits) of bitmap.
  //
  //  Blocks are present in the NSEC3 RR RDATA in increasing numerical
  //  order.
  //
  //     Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+
  //
  //     where "|" denotes concatenation.
  //
  //  Each bitmap encodes the low-order 8 bits of RR types within the
  //  window block, in network bit order.  The first bit is bit 0.  For
  //  window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
  //  to RR type 2 (NS), and so forth.  For window block 1, bit 1
  //  corresponds to RR type 257, bit 2 to RR type 258.  If a bit is set to
  //  1, it indicates that an RRSet of that type is present for the
  //  original owner name of the NSEC3 RR.  If a bit is set to 0, it
  //  indicates that no RRSet of that type is present for the original
  //  owner name of the NSEC3 RR.
  //
  //  Since bit 0 in window block 0 refers to the non-existing RR type 0,
  //  it MUST be set to 0.  After verification, the validator MUST ignore
  //  the value of bit 0 in window block 0.
  //
  //  Bits representing Meta-TYPEs or QTYPEs as specified in Section 3.1 of
  //  [RFC2929] or within the range reserved for assignment only to QTYPEs
  //  and Meta-TYPEs MUST be set to 0, since they do not appear in zone
  //  data.  If encountered, they must be ignored upon reading.
  //
  //  Blocks with no types present MUST NOT be included.  Trailing zero
  //  octets in the bitmap MUST be omitted.  The length of the bitmap of
  //  each block is determined by the type code with the largest numerical
  //  value, within that block, among the set of RR types present at the
  //  original owner name of the NSEC3 RR.  Trailing octets not specified
  //  MUST be interpreted as zero octets.
  NSEC3(NSEC3),

  // RFC 5155                         NSEC3                        March 2008
  //
  // 4.2.  NSEC3PARAM RDATA Wire Format
  //
  //  The RDATA of the NSEC3PARAM RR is as shown below:
  //
  //                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |   Hash Alg.   |     Flags     |          Iterations           |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |  Salt Length  |                     Salt                      /
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //  Hash Algorithm is a single octet.
  //
  //  Flags field is a single octet.
  //
  //  Iterations is represented as a 16-bit unsigned integer, with the most
  //  significant bit first.
  //
  //  Salt Length is represented as an unsigned octet.  Salt Length
  //  represents the length of the following Salt field in octets.  If the
  //  value is zero, the Salt field is omitted.
  //
  //  Salt, if present, is encoded as a sequence of binary octets.  The
  //  length of this field is determined by the preceding Salt Length
  //  field.
  NSEC3PARAM(NSEC3PARAM),

  // RFC 6891                   EDNS(0) Extensions                 April 2013
  // 6.1.2.  Wire Format
  //
  //        +------------+--------------+------------------------------+
  //        | Field Name | Field Type   | Description                  |
  //        +------------+--------------+------------------------------+
  //        | NAME       | domain name  | MUST be 0 (root domain)      |
  //        | TYPE       | u_int16_t    | OPT (41)                     |
  //        | CLASS      | u_int16_t    | requestor's UDP payload size |
  //        | TTL        | u_int32_t    | extended RCODE and flags     |
  //        | RDLEN      | u_int16_t    | length of all RDATA          |
  //        | RDATA      | octet stream | {attribute,value} pairs      |
  //        +------------+--------------+------------------------------+
  //
  // The variable part of an OPT RR may contain zero or more options in
  //    the RDATA.  Each option MUST be treated as a bit field.  Each option
  //    is encoded as:
  //
  //                   +0 (MSB)                            +1 (LSB)
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  //     0: |                          OPTION-CODE                          |
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  //     2: |                         OPTION-LENGTH                         |
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  //     4: |                                                               |
  //        /                          OPTION-DATA                          /
  //        /                                                               /
  //        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  OPT(OPT),

  // 3.3.12. PTR RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   PTRDNAME                    /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // PTRDNAME        A <domain-name> which points to some location in the
  //                 domain name space.
  //
  // PTR records cause no additional section processing.  These RRs are used
  // in special domains to point to some other location in the domain space.
  // These records are simple data, and don't imply any special processing
  // similar to that performed by CNAME, which identifies aliases.  See the
  // description of the IN-ADDR.ARPA domain for an example.
  PTR(Name),

  // RFC 2535 & 2931   DNS Security Extensions               March 1999
  // RFC 4034          DNSSEC Resource Records               March 2005
  //
  // 3.1.  RRSIG RDATA Wire Format
  //
  //    The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
  //    1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
  //    TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
  //    Inception field, a 2 octet Key tag, the Signer's Name field, and the
  //    Signature field.
  //
  //                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
  //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |        Type Covered           |  Algorithm    |     Labels    |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |                         Original TTL                          |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |                      Signature Expiration                     |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |                      Signature Inception                      |
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    |            Key Tag            |                               /
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
  //    /                                                               /
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //    /                                                               /
  //    /                            Signature                          /
  //    /                                                               /
  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  SIG(SIG),

  // 3.3.13. SOA RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                     MNAME                     /
  //     /                                               /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                     RNAME                     /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    SERIAL                     |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    REFRESH                    |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                     RETRY                     |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    EXPIRE                     |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     |                    MINIMUM                    |
  //     |                                               |
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // MNAME           The <domain-name> of the name server that was the
  //                 original or primary source of data for this zone.
  //
  // RNAME           A <domain-name> which specifies the mailbox of the
  //                 person responsible for this zone.
  //
  // SERIAL          The unsigned 32 bit version number of the original copy
  //                 of the zone.  Zone transfers preserve this value.  This
  //                 value wraps and should be compared using sequence space
  //                 arithmetic.
  //
  // REFRESH         A 32 bit time interval before the zone should be
  //                 refreshed.
  //
  // RETRY           A 32 bit time interval that should elapse before a
  //                 failed refresh should be retried.
  //
  // EXPIRE          A 32 bit time value that specifies the upper limit on
  //                 the time interval that can elapse before the zone is no
  //                 longer authoritative.
  //
  // MINIMUM         The unsigned 32 bit minimum TTL field that should be
  //                 exported with any RR from this zone.
  //
  // SOA records cause no additional section processing.
  //
  // All times are in units of seconds.
  //
  // Most of these fields are pertinent only for name server maintenance
  // operations.  However, MINIMUM is used in all query operations that
  // retrieve RRs from a zone.  Whenever a RR is sent in a response to a
  // query, the TTL field is set to the maximum of the TTL field from the RR
  // and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
  // bound on the TTL field for all RRs in a zone.  Note that this use of
  // MINIMUM should occur when the RRs are copied into the response and not
  // when the zone is loaded from a master file or via a zone transfer.  The
  // reason for this provison is to allow future dynamic update facilities to
  // change the SOA RR with known semantics.
  //SOA { mname: Name, rname: Name, serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32, },
  SOA(SOA),

  // RFC 2782                       DNS SRV RR                  February 2000
  //
  // The format of the SRV RR
  //
  //  _Service._Proto.Name TTL Class SRV Priority Weight Port Target
  SRV(SRV),

  // 3.3.14. TXT RDATA format
  //
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //     /                   TXT-DATA                    /
  //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  //
  // where:
  //
  // TXT-DATA        One or more <character-string>s.
  //
  // TXT RRs are used to hold descriptive text.  The semantics of the text
  // depends on the domain where it is found.
  TXT(TXT),


}

impl RData {
  pub fn parse(record_type: RecordType, tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<Self> {
    let rdata = match record_type {
      RecordType::A => RData::A(try!(rdata::a::parse(tokens))),
      RecordType::AAAA => RData::AAAA(try!(rdata::aaaa::parse(tokens))),
      RecordType::ANY => panic!("parsing ANY doesn't make sense"),
      RecordType::AXFR => panic!("parsing AXFR doesn't make sense"),
      RecordType::CNAME => RData::CNAME(try!(rdata::name::parse(tokens, origin))),
      RecordType::KEY => panic!("KEY should be dynamically generated"),
      RecordType::DNSKEY => panic!("DNSKEY should be dynamically generated"),
      RecordType::DS => panic!("DS should be dynamically generated"),
      RecordType::IXFR => panic!("parsing IXFR doesn't make sense"),
      RecordType::MX => RData::MX(try!(rdata::mx::parse(tokens, origin))),
      RecordType::NULL =>  RData::NULL(try!(rdata::null::parse(tokens))),
      RecordType::NS => RData::NS(try!(rdata::name::parse(tokens, origin))),
      RecordType::NSEC => panic!("NSEC should be dynamically generated"),
      RecordType::NSEC3 => panic!("NSEC3 should be dynamically generated"),
      RecordType::NSEC3PARAM => panic!("NSEC3PARAM should be dynamically generated"),
      RecordType::OPT => panic!("parsing OPT doesn't make sense"),
      RecordType::PTR => RData::PTR(try!(rdata::name::parse(tokens, origin))),
      RecordType::RRSIG => panic!("RRSIG should be dynamically generated"),
      RecordType::SIG => panic!("parsing SIG doesn't make sense"),
      RecordType::SOA => RData::SOA(try!(rdata::soa::parse(tokens, origin))),
      RecordType::SRV => RData::SRV(try!(rdata::srv::parse(tokens, origin))),
      RecordType::TXT => RData::TXT(try!(rdata::txt::parse(tokens))),
    };

    Ok(rdata)
  }

  fn to_bytes(&self) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
      let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
      self.emit(&mut encoder).unwrap_or_else(|_| { warn!("could not encode RDATA: {:?}", self); ()});
    }
    buf
  }

  pub fn read(decoder: &mut BinDecoder, record_type: RecordType, rdata_length: u16) -> DecodeResult<Self> {
    let start_idx = decoder.index();

    let result = match record_type {
      RecordType::A => {debug!("reading A"); RData::A(try!(rdata::a::read(decoder))) },
      RecordType::AAAA => {debug!("reading AAAA"); RData::AAAA(try!(rdata::aaaa::read(decoder))) },
      rt @ RecordType::ANY => return Err(DecodeError::UnknownRecordTypeValue(rt.into())),
      rt @ RecordType::AXFR => return Err(DecodeError::UnknownRecordTypeValue(rt.into())),
      RecordType::CNAME => {debug!("reading CNAME"); RData::CNAME(try!(rdata::name::read(decoder))) },
      RecordType::KEY => {debug!("reading KEY"); RData::KEY(try!(rdata::dnskey::read(decoder, rdata_length))) },
      RecordType::DNSKEY => {debug!("reading DNSKEY"); RData::DNSKEY(try!(rdata::dnskey::read(decoder, rdata_length))) },
      RecordType::DS => {debug!("reading DS"); RData::DS(try!(rdata::ds::read(decoder, rdata_length))) },
      rt @ RecordType::IXFR => return Err(DecodeError::UnknownRecordTypeValue(rt.into())),
      RecordType::MX => {debug!("reading MX"); RData::MX(try!(rdata::mx::read(decoder))) },
      RecordType::NULL => {debug!("reading NULL"); RData::NULL(try!(rdata::null::read(decoder, rdata_length))) },
      RecordType::NS => {debug!("reading NS"); RData::NS(try!(rdata::name::read(decoder))) },
      RecordType::NSEC => {debug!("reading NSEC"); RData::NSEC(try!(rdata::nsec::read(decoder, rdata_length))) },
      RecordType::NSEC3 => {debug!("reading NSEC3"); RData::NSEC3(try!(rdata::nsec3::read(decoder, rdata_length))) },
      RecordType::NSEC3PARAM => {debug!("reading NSEC3PARAM"); RData::NSEC3PARAM(try!(rdata::nsec3param::read(decoder))) },
      RecordType::OPT => {debug!("reading OPT"); RData::OPT(try!(rdata::opt::read(decoder, rdata_length))) },
      RecordType::PTR => {debug!("reading PTR"); RData::PTR(try!(rdata::name::read(decoder))) },
      RecordType::RRSIG => {debug!("reading RRSIG"); RData::SIG(try!(rdata::sig::read(decoder, rdata_length))) },
      RecordType::SIG => {debug!("reading SIG"); RData::SIG(try!(rdata::sig::read(decoder, rdata_length))) },
      RecordType::SOA => {debug!("reading SOA"); RData::SOA(try!(rdata::soa::read(decoder))) },
      RecordType::SRV => {debug!("reading SRV"); RData::SRV(try!(rdata::srv::read(decoder))) },
      RecordType::TXT => {debug!("reading TXT"); RData::TXT(try!(rdata::txt::read(decoder, rdata_length))) },
    };

    // we should have read rdata_length, but we did not
    let read = decoder.index() - start_idx;
    if read != rdata_length as usize {
      return Err(DecodeError::IncorrectRDataLengthRead(read, rdata_length as usize))
    }
    Ok(result)
  }

  pub fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    match *self {
      RData::A(ref address) => rdata::a::emit(encoder, address),
      RData::AAAA(ref address) => rdata::aaaa::emit(encoder, address),
      RData::CNAME(ref name) => rdata::name::emit(encoder, name),
      RData::DS(ref ds) => rdata::ds::emit(encoder, ds),
      RData::KEY(ref key) => rdata::dnskey::emit(encoder, key),
      RData::DNSKEY(ref dnskey) => rdata::dnskey::emit(encoder, dnskey),
      RData::MX(ref mx) => rdata::mx::emit(encoder, mx),
      RData::NULL(ref null) => rdata::null::emit(encoder, null),
      RData::NS(ref name) => rdata::name::emit(encoder, name),
      RData::NSEC(ref nsec) => rdata::nsec::emit(encoder, nsec),
      RData::NSEC3(ref nsec3) => rdata::nsec3::emit(encoder, nsec3),
      RData::NSEC3PARAM(ref nsec3param) => rdata::nsec3param::emit(encoder, nsec3param),
      RData::OPT(ref opt) => rdata::opt::emit(encoder, opt),
      RData::PTR(ref name) => rdata::name::emit(encoder, name),
      RData::SIG(ref sig) => rdata::sig::emit(encoder, sig),
      RData::SOA(ref soa) => rdata::soa::emit(encoder, soa),
      RData::SRV(ref srv) => rdata::srv::emit(encoder, srv),
      RData::TXT(ref txt) => rdata::txt::emit(encoder, txt),
    }
  }
}

// TODO: this is kinda broken right now since it can't cover all types.
#[cfg(test)]
impl<'a> From<&'a RData> for RecordType {
  fn from(rdata: &'a RData) -> Self {
    match *rdata {
      RData::A(..) => RecordType::A,
      RData::AAAA(..) => RecordType::AAAA,
      RData::CNAME(..) => RecordType::CNAME,
      RData::DS(..) => RecordType::DS,
      RData::KEY(..) => RecordType::KEY,
      RData::DNSKEY(..) => RecordType::DNSKEY,
      RData::MX(..) => RecordType::MX,
      RData::NS(..) => RecordType::NS,
      RData::NSEC(..) => RecordType::NSEC,
      RData::NSEC3(..) => RecordType::NSEC3,
      RData::NSEC3PARAM(..) => RecordType::NSEC3PARAM,
      RData::NULL(..) => RecordType::NULL,
      RData::OPT(..) => RecordType::OPT,
      RData::PTR(..) => RecordType::PTR,
      RData::SIG(..) => RecordType::SIG,
      RData::SOA(..) => RecordType::SOA,
      RData::SRV(..) => RecordType::SRV,
      RData::TXT(..) => RecordType::TXT,
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
  use ::serialize::binary::*;
  use ::serialize::binary::bin_tests::test_emit_data_set;
  use ::rr::domain::Name;
  use ::rr::rdata::{MX, SOA, SRV, TXT};

  fn get_data() -> Vec<(RData, Vec<u8>)> {
    vec![
    (RData::CNAME(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])), vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    (RData::MX(MX::new(256, Name::with_labels(vec!["n".to_string()]))), vec![1,0,1,b'n',0]),
    (RData::NS(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])), vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    (RData::PTR(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])), vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    (RData::SOA(SOA::new(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
                         Name::with_labels(vec!["xxx".to_string(),"example".to_string(),"com".to_string()]),
                         u32::max_value(), -1 as i32, -1 as i32, -1 as i32, u32::max_value())),
    vec![3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0,
    3,b'x',b'x',b'x',0xC0, 0x04,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF]),
    (RData::TXT(TXT::new(vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()])),
    vec![6,b'a',b'b',b'c',b'd',b'e',b'f', 3,b'g',b'h',b'i', 0, 1,b'j']),
    (RData::A(Ipv4Addr::from_str("0.0.0.0").unwrap()), vec![0,0,0,0]),
    (RData::AAAA(Ipv6Addr::from_str("::").unwrap()), vec![0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]),
    (RData::SRV(SRV::new(1, 2, 3, Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]))), vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]),
    ]
  }

  // TODO this test kinda sucks, shows the problem with not storing the binary parts
  #[test]
  fn test_order() {
    let ordered: Vec<RData> = vec![
      RData::A(Ipv4Addr::from_str("0.0.0.0").unwrap()),
      RData::AAAA(Ipv6Addr::from_str("::").unwrap()),
      RData::SRV(SRV::new(1, 2, 3, Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]))),
      RData::MX(MX::new(256, Name::with_labels(vec!["n".to_string()]))),
      RData::CNAME(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])),
      RData::PTR(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])),
      RData::NS(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])),
      RData::SOA(SOA::new(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
                          Name::with_labels(vec!["xxx".to_string(),"example".to_string(),"com".to_string()]),
                          u32::max_value(), -1 as i32, -1 as i32, -1 as i32, u32::max_value())),
      RData::TXT(TXT::new(vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()])),
    ];
    let mut unordered = vec![
      RData::CNAME(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])),
      RData::MX(MX::new(256, Name::with_labels(vec!["n".to_string()]))),
      RData::PTR(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])),
      RData::NS(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()])),
      RData::SOA(SOA::new(Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]),
                          Name::with_labels(vec!["xxx".to_string(),"example".to_string(),"com".to_string()]),
                          u32::max_value(), -1 as i32, -1 as i32, -1 as i32, u32::max_value())),
      RData::TXT(TXT::new(vec!["abcdef".to_string(), "ghi".to_string(), "".to_string(), "j".to_string()])),
      RData::A(Ipv4Addr::from_str("0.0.0.0").unwrap()),
      RData::AAAA(Ipv6Addr::from_str("::").unwrap()),
      RData::SRV(SRV::new(1, 2, 3, Name::with_labels(vec!["www".to_string(),"example".to_string(),"com".to_string()]))),
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

      assert_eq!(RData::read(&mut decoder, ::rr::record_type::RecordType::from(&expect), length).unwrap(), expect);
    }
  }

  #[test]
  fn test_write_to() {
    test_emit_data_set(get_data(), |e,d| d.emit(e));
  }
}
