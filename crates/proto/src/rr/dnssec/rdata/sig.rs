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

//! signature record for signing queries, updates, and responses
use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::dnssec::Algorithm;
use crate::rr::{Name, RecordType};
use crate::serialize::binary::*;

/// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4), Domain Name System Security Extensions, March 1999
///
/// NOTE: RFC 2535 was obsoleted with 4034+, with the exception of the
///  usage for UPDATE, which is what this implementation is for.
///
/// ```text
/// 4.1 SIG RDATA Format
///
///  The RDATA portion of a SIG RR is as shown below.  The integrity of
///  the RDATA information is protected by the signature field.
///
///  1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        type covered           |  algorithm    |     labels    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         original TTL                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      signature expiration                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      signature inception                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            key  tag           |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
/// |                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
/// /                                                               /
/// /                            signature                          /
/// /                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ```
/// [RFC 2931](https://tools.ietf.org/html/rfc2931), DNS Request and Transaction Signatures, September 2000
///
/// NOTE: 2931 updates SIG0 to clarify certain particulars...
///
/// ```text
/// RFC 2931                       DNS SIG(0)                 September 2000
///
/// 3. The SIG(0) Resource Record
///
///    The structure of and type number of SIG resource records (RRs) is
///    given in [RFC 2535] Section 4.1.  However all of Section 4.1.8.1 and
///    the parts of Sections 4.2 and 4.3 related to SIG(0) should be
///    considered replaced by the material below.  Any conflict between [RFC
///    2535] and this document concerning SIG(0) RRs should be resolved in
///    favor of this document.
///
///    For all transaction SIG(0)s, the signer field MUST be a name of the
///    originating host and there MUST be a KEY RR at that name with the
///    public key corresponding to the private key used to calculate the
///    signature.  (The host domain name used may be the inverse IP address
///    mapping name for an IP address of the host if the relevant KEY is
///    stored there.)
///
///    For all SIG(0) RRs, the owner name, class, TTL, and original TTL, are
///    meaningless.  The TTL fields SHOULD be zero and the CLASS field
///    SHOULD be ANY.  To conserve space, the owner name SHOULD be root (a
///    single zero octet).  When SIG(0) authentication on a response is
///    desired, that SIG RR MUST be considered the highest priority of any
///    additional information for inclusion in the response. If the SIG(0)
///    RR cannot be added without causing the message to be truncated, the
///    server MUST alter the response so that a SIG(0) can be included.
///    This response consists of only the question and a SIG(0) record, and
///    has the TC bit set and RCODE 0 (NOERROR).  The client should at this
///    point retry the request using TCP.
///
/// 3.1 Calculating Request and Transaction SIGs
///
///    A DNS request may be optionally signed by including one SIG(0)s at
///    the end of the query additional information section.  Such a SIG is
///    identified by having a "type covered" field of zero. It signs the
///    preceding DNS request message including DNS header but not including
///    the UDP/IP header and before the request RR counts have been adjusted
///    for the inclusions of the request SIG(0).
///
///    It is calculated by using a "data" (see [RFC 2535], Section 4.1.8) of
///    (1) the SIG's RDATA section entirely omitting (not just zeroing) the
///    signature subfield itself, (2) the DNS query messages, including DNS
///    header, but not the UDP/IP header and before the reply RR counts have
///    been adjusted for the inclusion of the SIG(0).  That is
///
///       data = RDATA | request - SIG(0)
///
///    where "|" is concatenation and RDATA is the RDATA of the SIG(0) being
///    calculated less the signature itself.
///
///    Similarly, a SIG(0) can be used to secure a response and the request
///    that produced it.  Such transaction signatures are calculated by
///    using a "data" of (1) the SIG's RDATA section omitting the signature
///    itself, (2) the entire DNS query message that produced this response,
///    including the query's DNS header but not its UDP/IP header, and (3)
///    the entire DNS response message, including DNS header but not the
///    UDP/IP header and before the response RR counts have been adjusted
///    for the inclusion of the SIG(0).
///
///    That is
///
///       data = RDATA | full query | response - SIG(0)
///
///    where "|" is concatenation and RDATA is the RDATA of the SIG(0) being
///    calculated less the signature itself.
///
///    Verification of a response SIG(0) (which is signed by the server host
///    key, not the zone key) by the requesting resolver shows that the
///    query and response were not tampered with in transit, that the
///    response corresponds to the intended query, and that the response
///    comes from the queried server.
///
///    In the case of a DNS message via TCP, a SIG(0) on the first data
///    packet is calculated with "data" as above and for each subsequent
///    packet, it is calculated as follows:
///
///       data = RDATA | DNS payload - SIG(0) | previous packet
///
///    where "|" is concatenations, RDATA is as above, and previous packet
///    is the previous DNS payload including DNS header and the SIG(0) but
///    not the TCP/IP header.  Support of SIG(0) for TCP is OPTIONAL.  As an
///    alternative, TSIG may be used after, if necessary, setting up a key
///    with TKEY [RFC 2930].
///
///    Except where needed to authenticate an update, TKEY, or similar
///    privileged request, servers are not required to check a request
///    SIG(0).
///
///    Note: requests and responses can either have a single TSIG or one
///    SIG(0) but not both a TSIG and a SIG(0).
///
/// 3.2 Processing Responses and SIG(0) RRs
///
///    If a SIG RR is at the end of the additional information section of a
///    response and has a type covered of zero, it is a transaction
///    signature covering the response and the query that produced the
///    response.  For TKEY responses, it MUST be checked and the message
///    rejected if the checks fail unless otherwise specified for the TKEY
///    mode in use.  For all other responses, it MAY be checked and the
///    message rejected if the checks fail.
///
///    If a response's SIG(0) check succeed, such a transaction
///    authentication SIG does NOT directly authenticate the validity any
///    data-RRs in the message.  However, it authenticates that they were
///    sent by the queried server and have not been diddled.  (Only a proper
///    SIG(0) RR signed by the zone or a key tracing its authority to the
///    zone or to static resolver configuration can directly authenticate
///
///    data-RRs, depending on resolver policy.) If a resolver or server does
///    not implement transaction and/or request SIGs, it MUST ignore them
///    without error where they are optional and treat them as failing where
///    they are required.
///
/// 3.3 SIG(0) Lifetime and Expiration
///
///    The inception and expiration times in SIG(0)s are for the purpose of
///    resisting replay attacks.  They should be set to form a time bracket
///    such that messages outside that bracket can be ignored.  In IP
///    networks, this time bracket should not normally extend further than 5
///    minutes into the past and 5 minutes into the future.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SIG {
    type_covered: RecordType,
    algorithm: Algorithm,
    num_labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: Name,
    sig: Vec<u8>,
}

impl SIG {
    /// Creates a new SIG record data, used for both RRSIG and SIG(0) records.
    ///
    /// # Arguments
    ///
    /// * `type_covered` - The `RecordType` which this signature covers, should be NULL for SIG(0).
    /// * `algorithm` - The `Algorithm` used to generate the `signature`.
    /// * `num_labels` - The number of labels in the name, should be less 1 for *.name labels,
    ///                  see `Name::num_labels()`.
    /// * `original_ttl` - The TTL for the RRSet stored in the zone, should be 0 for SIG(0).
    /// * `sig_expiration` - Timestamp at which this signature is no longer valid, very important to
    ///                      keep this low, < +5 minutes to limit replay attacks.
    /// * `sig_inception` - Timestamp when this signature was generated.
    /// * `key_tag` - See the key_tag generation in `rr::dnssec::Signer::key_tag()`.
    /// * `signer_name` - Domain name of the server which was used to generate the signature.
    /// * `sig` - signature stored in this record.
    ///
    /// # Return value
    ///
    /// The new SIG record data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_covered: RecordType,
        algorithm: Algorithm,
        num_labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signer_name: Name,
        sig: Vec<u8>,
    ) -> Self {
        Self {
            type_covered,
            algorithm,
            num_labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name,
            sig,
        }
    }

    /// Add actual signature value to existing SIG record data.
    ///
    /// # Arguments
    ///
    /// * `signature` - signature to be stored in this record.
    ///
    /// # Return value
    ///
    /// The new SIG record data.
    pub fn set_sig(self, signature: Vec<u8>) -> Self {
        Self {
            type_covered: self.type_covered,
            algorithm: self.algorithm,
            num_labels: self.num_labels,
            original_ttl: self.original_ttl,
            sig_expiration: self.sig_expiration,
            sig_inception: self.sig_inception,
            key_tag: self.key_tag,
            signer_name: self.signer_name,
            sig: signature,
        }
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.1), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.1 Type Covered Field
    ///
    ///  The "type covered" is the type of the other RRs covered by this SIG.
    /// ```
    pub fn type_covered(&self) -> RecordType {
        self.type_covered
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.2), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.2 Algorithm Number Field
    ///
    ///  This octet is as described in section 3.2.
    /// ```
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.3), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.3 Labels Field
    ///
    ///  The "labels" octet is an unsigned count of how many labels there are
    ///  in the original SIG RR owner name not counting the null label for
    ///  root and not counting any initial "*" for a wildcard.  If a secured
    ///  retrieval is the result of wild card substitution, it is necessary
    ///  for the resolver to use the original form of the name in verifying
    ///  the digital signature.  This field makes it easy to determine the
    ///  original form.
    ///
    ///  If, on retrieval, the RR appears to have a longer name than indicated
    ///  by "labels", the resolver can tell it is the result of wildcard
    ///  substitution.  If the RR owner name appears to be shorter than the
    ///  labels count, the SIG RR must be considered corrupt and ignored.  The
    ///  maximum number of labels allowed in the current DNS is 127 but the
    ///  entire octet is reserved and would be required should DNS names ever
    ///  be expanded to 255 labels.  The following table gives some examples.
    ///  The value of "labels" is at the top, the retrieved owner name on the
    ///  left, and the table entry is the name to use in signature
    ///  verification except that "bad" means the RR is corrupt.
    ///
    ///  labels= |  0  |   1  |    2   |      3   |      4   |
    ///  --------+-----+------+--------+----------+----------+
    ///         .|   . | bad  |  bad   |    bad   |    bad   |
    ///        d.|  *. |   d. |  bad   |    bad   |    bad   |
    ///      c.d.|  *. | *.d. |   c.d. |    bad   |    bad   |
    ///    b.c.d.|  *. | *.d. | *.c.d. |   b.c.d. |    bad   |
    ///  a.b.c.d.|  *. | *.d. | *.c.d. | *.b.c.d. | a.b.c.d. |
    /// ```
    pub fn num_labels(&self) -> u8 {
        self.num_labels
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.4), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.4 Original TTL Field
    ///
    ///  The "original TTL" field is included in the RDATA portion to avoid
    ///  (1) authentication problems that caching servers would otherwise
    ///  cause by decrementing the real TTL field and (2) security problems
    ///  that unscrupulous servers could otherwise cause by manipulating the
    ///  real TTL field.  This original TTL is protected by the signature
    ///  while the current TTL field is not.
    ///
    ///  NOTE:  The "original TTL" must be restored into the covered RRs when
    ///  the signature is verified (see Section 8).  This generally implies
    ///  that all RRs for a particular type, name, and class, that is, all the
    ///  RRs in any particular RRset, must have the same TTL to start with.
    /// ```
    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.5), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.5 Signature Expiration and Inception Fields
    ///
    ///  The SIG is valid from the "signature inception" time until the
    ///  "signature expiration" time.  Both are unsigned numbers of seconds
    ///  since the start of 1 January 1970, GMT, ignoring leap seconds.  (See
    ///  also Section 4.4.)  Ring arithmetic is used as for DNS SOA serial
    ///  numbers [RFC 1982] which means that these times can never be more
    ///  than about 68 years in the past or the future.  This means that these
    ///  times are ambiguous modulo ~136.09 years.  However there is no
    ///  security flaw because keys are required to be changed to new random
    ///  keys by [RFC 2541] at least every five years.  This means that the
    ///  probability that the same key is in use N*136.09 years later should
    ///  be the same as the probability that a random guess will work.
    ///
    ///  A SIG RR may have an expiration time numerically less than the
    ///  inception time if the expiration time is near the 32 bit wrap around
    ///  point and/or the signature is long lived.
    ///
    ///  (To prevent misordering of network requests to update a zone
    ///  dynamically, monotonically increasing "signature inception" times may
    ///  be necessary.)
    ///
    ///  A secure zone must be considered changed for SOA serial number
    ///  purposes not only when its data is updated but also when new SIG RRs
    ///  are inserted (ie, the zone or any part of it is re-signed).
    /// ```
    pub fn sig_expiration(&self) -> u32 {
        self.sig_expiration
    }

    /// see `get_sig_expiration`
    pub fn sig_inception(&self) -> u32 {
        self.sig_inception
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.6), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.6 Key Tag Field
    ///
    ///  The "key Tag" is a two octet quantity that is used to efficiently
    ///  select between multiple keys which may be applicable and thus check
    ///  that a public key about to be used for the computationally expensive
    ///  effort to check the signature is possibly valid.  For algorithm 1
    ///  (MD5/RSA) as defined in [RFC 2537], it is the next to the bottom two
    ///  octets of the public key modulus needed to decode the signature
    ///  field.  That is to say, the most significant 16 of the least
    ///  significant 24 bits of the modulus in network (big endian) order. For
    ///  all other algorithms, including private algorithms, it is calculated
    ///  as a simple checksum of the KEY RR as described in Appendix C.
    /// ```
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.7), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.7 Signer's Name Field
    ///
    ///  The "signer's name" field is the domain name of the signer generating
    ///  the SIG RR.  This is the owner name of the public KEY RR that can be
    ///  used to verify the signature.  It is frequently the zone which
    ///  contained the RRset being authenticated.  Which signers should be
    ///  authorized to sign what is a significant resolver policy question as
    ///  discussed in Section 6. The signer's name may be compressed with
    ///  standard DNS name compression when being transmitted over the
    ///  network.
    /// ```
    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    /// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-4.1.8), Domain Name System Security Extensions, March 1999
    ///
    /// ```text
    /// 4.1.8 Signature Field
    ///
    ///  The actual signature portion of the SIG RR binds the other RDATA
    ///  fields to the RRset of the "type covered" RRs with that owner name
    ///  and class.  This covered RRset is thereby authenticated.  To
    ///  accomplish this, a data sequence is constructed as follows:
    ///
    ///  data = RDATA | RR(s)...
    ///
    ///  where "|" is concatenation,
    ///
    ///  RDATA is the wire format of all the RDATA fields in the SIG RR itself
    ///  (including the canonical form of the signer's name) before but not
    ///  including the signature, and
    ///
    ///  RR(s) is the RRset of the RR(s) of the type covered with the same
    ///  owner name and class as the SIG RR in canonical form and order as
    ///  defined in Section 8.
    ///
    ///  How this data sequence is processed into the signature is algorithm
    ///  dependent.  These algorithm dependent formats and procedures are
    ///  described in separate documents (Section 3.2).
    ///
    ///  SIGs SHOULD NOT be included in a zone for any "meta-type" such as
    ///  ANY, AXFR, etc. (but see section 5.6.2 with regard to IXFR).
    /// ```
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<SIG> {
    let start_idx = decoder.index();

    // TODO should we verify here? or elsewhere...
    let type_covered = RecordType::read(decoder)?;
    let algorithm = Algorithm::read(decoder)?;
    let num_labels = decoder.read_u8()?.unverified(/*technically valid as any u8*/);
    let original_ttl = decoder.read_u32()?.unverified(/*valid as any u32*/);
    let sig_expiration =
        decoder.read_u32()?.unverified(/*valid as any u32, in practice should be in the future*/);
    let sig_inception = decoder.read_u32()?.unverified(/*valid as any u32, in practice should be before expiration*/);
    let key_tag = decoder.read_u16()?.unverified(/*valid as any u16*/);
    let signer_name = Name::read(decoder)?;

    // read the signature, this will vary buy key size
    let sig_len = rdata_length
        .map(|u| u as usize)
        .checked_sub(decoder.index() - start_idx)
        .map_err(|_| ProtoError::from("invalid rdata length in SIG"))?
        .unverified(/*used only as length safely*/);
    let sig = decoder
        .read_vec(sig_len)?
        .unverified(/*will fail in usage if invalid*/);

    Ok(SIG::new(
        type_covered,
        algorithm,
        num_labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        sig,
    ))
}

/// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-6), DNSSEC Resource Records, March 2005
///
/// This is accurate for all currently known name records.
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
pub fn emit(encoder: &mut BinEncoder<'_>, sig: &SIG) -> ProtoResult<()> {
    let is_canonical_names = encoder.is_canonical_names();

    sig.type_covered().emit(encoder)?;
    sig.algorithm().emit(encoder)?;
    encoder.emit(sig.num_labels())?;
    encoder.emit_u32(sig.original_ttl())?;
    encoder.emit_u32(sig.sig_expiration())?;
    encoder.emit_u32(sig.sig_inception())?;
    encoder.emit_u16(sig.key_tag())?;
    sig.signer_name()
        .emit_with_lowercase(encoder, is_canonical_names)?;
    encoder.emit_vec(sig.sig())?;
    Ok(())
}

/// specifically for outputting the RData for an RRSIG, with signer_name in canonical form
#[allow(clippy::too_many_arguments)]
pub fn emit_pre_sig(
    encoder: &mut BinEncoder<'_>,
    type_covered: RecordType,
    algorithm: Algorithm,
    num_labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: &Name,
) -> ProtoResult<()> {
    type_covered.emit(encoder)?;
    algorithm.emit(encoder)?;
    encoder.emit(num_labels)?;
    encoder.emit_u32(original_ttl)?;
    encoder.emit_u32(sig_expiration)?;
    encoder.emit_u32(sig_inception)?;
    encoder.emit_u16(key_tag)?;
    signer_name.emit_as_canonical(encoder, true)?;
    Ok(())
}

/// [RFC 2535](https://tools.ietf.org/html/rfc2535#section-7.2), Domain Name System Security Extensions, March 1999
///
/// ```text
/// 7.2 Presentation of SIG RRs
///
///    A data SIG RR may be represented as a single logical line in a zone
///    data file [RFC 1033] but there are some special considerations as
///    described below.  (It does not make sense to include a transaction or
///    request authenticating SIG RR in a file as they are a transient
///    authentication that covers data including an ephemeral transaction
///    number and so must be calculated in real time.)
///
///    There is no particular problem with the signer, covered type, and
///    times.  The time fields appears in the form YYYYMMDDHHMMSS where YYYY
///    is the year, the first MM is the month number (01-12), DD is the day
///    of the month (01-31), HH is the hour in 24 hours notation (00-23),
///    the second MM is the minute (00-59), and SS is the second (00-59).
///
///    The original TTL field appears as an unsigned integer.
///
///    If the original TTL, which applies to the type signed, is the same as
///    the TTL of the SIG RR itself, it may be omitted.  The date field
///    which follows it is larger than the maximum possible TTL so there is
///    no ambiguity.
///
///    The "labels" field appears as an unsigned integer.
///
///    The key tag appears as an unsigned number.
///
///    However, the signature itself can be very long.  It is the last data
///    field and is represented in base 64 (see Appendix A) and may be
///    divided up into any number of white space separated substrings, down
///    to single base 64 digits, which are concatenated to obtain the full
///    signature.  These substrings can be split between lines using the
///    standard parenthesis.
///
///   foo.nil.    SIG NXT 1 2 ( ;type-cov=NXT, alg=1, labels=2
///     19970102030405 ;signature expiration
///     19961211100908 ;signature inception
///     2143           ;key identifier
///     foo.nil.       ;signer
///     AIYADP8d3zYNyQwW2EM4wXVFdslEJcUx/fxkfBeH1El4ixPFhpfHFElxbvKoWmvjDTCm
///     fiYy2X+8XpFjwICHc398kzWsTMKlxovpz2FnCTM= ;signature (640 bits)
/// ```
impl fmt::Display for SIG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{ty_covered} {alg} {num_labels} {original_ttl} {expire} {inception} {tag} {signer} {sig}",
            ty_covered = self.type_covered,
            alg = self.algorithm,
            num_labels = self.num_labels,
            original_ttl = self.original_ttl,
            expire = self.sig_expiration,
            inception = self.sig_inception,
            tag = self.key_tag,
            signer = self.signer_name,
            sig = data_encoding::BASE64.encode(&self.sig)
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        use std::str::FromStr;

        let rdata = SIG::new(
            RecordType::NULL,
            Algorithm::RSASHA256,
            0,
            0,
            2,
            1,
            5,
            Name::from_str("www.example.com").unwrap(),
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 29, 31,
            ], // 32 bytes for SHA256
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = read(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
