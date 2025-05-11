// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! signature record for signing queries, updates, and responses
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::DNSSECRData;
use crate::{
    dnssec::{Algorithm, SigSigner},
    error::{ProtoError, ProtoResult},
    rr::{Name, RData, RecordData, RecordDataDecodable, RecordSet, RecordType, SerialNumber},
    serialize::binary::{
        BinDecodable, BinDecoder, BinEncodable, BinEncoder, RDataEncoding, Restrict, RestrictedMath,
    },
};

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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SIG {
    pub(crate) input: SigInput,
    pub(crate) sig: Vec<u8>,
}

impl SIG {
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

    /// The input data used to create the signature.
    pub fn input(&self) -> &SigInput {
        &self.input
    }
}

impl BinEncodable for SIG {
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
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let mut encoder = encoder.with_rdata_behavior(RDataEncoding::Canonical);
        self.input.emit(&mut encoder)?;
        encoder.emit_vec(&self.sig)?;
        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for SIG {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        // TODO should we verify here? or elsewhere...
        let type_covered = RecordType::read(decoder)?;
        let algorithm = Algorithm::read(decoder)?;
        let num_labels = decoder.read_u8()?.unverified(/*technically valid as any u8*/);
        let original_ttl = decoder.read_u32()?.unverified(/*valid as any u32*/);
        let sig_expiration = SerialNumber(
            decoder.read_u32()?.unverified(/*valid as any u32, in practice should be in the future*/),
        );
        let sig_inception = SerialNumber(
            decoder.read_u32()?.unverified(/*valid as any u32, in practice should be before expiration*/),
        );
        let key_tag = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let signer_name = Name::read(decoder)?;

        let input = SigInput {
            type_covered,
            algorithm,
            num_labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name,
        };

        // read the signature, this will vary buy key size
        let sig_len = length
        .map(|u| u as usize)
        .checked_sub(decoder.index() - start_idx)
        .map_err(|_| ProtoError::from("invalid rdata length in SIG"))?
        .unverified(/*used only as length safely*/);
        let sig = decoder
        .read_vec(sig_len)?
        .unverified(/*will fail in usage if invalid*/);
        Ok(Self { input, sig })
    }
}

impl RecordData for SIG {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::SIG(csync)) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::SIG
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::SIG(self))
    }
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
        write!(
            f,
            "{ty_covered} {alg} {num_labels} {original_ttl} {expire} {inception} {tag} {signer} {sig}",
            ty_covered = self.input.type_covered,
            alg = self.input.algorithm,
            num_labels = self.input.num_labels,
            original_ttl = self.input.original_ttl,
            expire = self.input.sig_expiration.0,
            inception = self.input.sig_inception.0,
            tag = self.input.key_tag,
            signer = self.input.signer_name,
            sig = data_encoding::BASE64.encode(&self.sig)
        )
    }
}

/// Input for a SIG or RRSIG record signature.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SigInput {
    /// `RecordType` which this signature covers, should be NULL for SIG(0).
    pub type_covered: RecordType,
    /// `Algorithm` used to generate the `signature`.
    pub algorithm: Algorithm,
    /// Number of labels in the name, should be less 1 for *.name labels, see
    /// `Name::num_labels()`.
    pub num_labels: u8,
    /// * TTL for the RRSet stored in the zone, should be 0 for SIG(0).
    pub original_ttl: u32,
    /// Timestamp at which this signature is no longer valid
    ///
    /// Very important to keep this low, < +5 minutes to limit replay attacks.
    pub sig_expiration: SerialNumber,
    /// * Timestamp when this signature was generated.
    pub sig_inception: SerialNumber,
    /// * See the key_tag generation in `rr::dnssec::Signer::key_tag()`.
    pub key_tag: u16,
    /// * Domain name of the server which was used to generate the signature.
    pub signer_name: Name,
}

impl SigInput {
    /// Create a new `SigInput` from the given input parameters.
    pub fn from_rrset(
        rr_set: &RecordSet,
        expiration: OffsetDateTime,
        inception: OffsetDateTime,
        signer: &SigSigner,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            type_covered: rr_set.record_type(),
            algorithm: signer.key().algorithm(),
            num_labels: rr_set.name().num_labels(),
            original_ttl: rr_set.ttl(),
            sig_expiration: SerialNumber(expiration.unix_timestamp() as u32),
            sig_inception: SerialNumber(inception.unix_timestamp() as u32),
            key_tag: signer.calculate_key_tag()?,
            signer_name: signer.signer_name().clone(),
        })
    }
}

impl BinEncodable for SigInput {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let mut encoder = encoder.with_rdata_behavior(RDataEncoding::Canonical);
        // specifically for outputting the RData for an RRSIG, with signer_name in canonical form
        self.type_covered.emit(&mut encoder)?;
        self.algorithm.emit(&mut encoder)?;
        encoder.emit(self.num_labels)?;
        encoder.emit_u32(self.original_ttl)?;
        encoder.emit_u32(self.sig_expiration.0)?;
        encoder.emit_u32(self.sig_inception.0)?;
        encoder.emit_u16(self.key_tag)?;
        self.signer_name.emit(&mut encoder)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use super::*;

    #[test]
    fn test() {
        use core::str::FromStr;

        let input = SigInput {
            type_covered: RecordType::NULL,
            algorithm: Algorithm::RSASHA256,
            num_labels: 0,
            original_ttl: 0,
            sig_expiration: SerialNumber(2),
            sig_inception: SerialNumber(1),
            key_tag: 5,
            signer_name: Name::from_str("www.example.com.").unwrap(),
        };
        let rdata = SIG {
            input,
            sig: vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 29, 31,
            ], // 32 bytes for SHA256
        };

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = SIG::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
