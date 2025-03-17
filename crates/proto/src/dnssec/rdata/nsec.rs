// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! NSEC record types

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::{Name, RData, RecordData, RecordDataDecodable, RecordType, RecordTypeSet};
use crate::serialize::binary::*;

use super::DNSSECRData;

/// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-4), DNSSEC Resource Records, March 2005
///
/// ```text
/// 4.1.  NSEC RDATA Wire Format
///
///    The RDATA of the NSEC RR is as shown below:
///
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                      Next Domain Name                         /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                       Type Bit Maps                           /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// 4.1.3.  Inclusion of Wildcard Names in NSEC RDATA
///
///    If a wildcard owner name appears in a zone, the wildcard label ("*")
///    is treated as a literal symbol and is treated the same as any other
///    owner name for the purposes of generating NSEC RRs.  Wildcard owner
///    names appear in the Next Domain Name field without any wildcard
///    expansion.  [RFC4035] describes the impact of wildcards on
///    authenticated denial of existence.
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NSEC {
    next_domain_name: Name,
    type_bit_maps: RecordTypeSet,
}

impl NSEC {
    /// Constructs a new NSEC RData, warning this won't guarantee that the NSEC covers itself
    ///  which it should at it's own name.
    ///
    /// # Arguments
    ///
    /// * `next_domain_name` - the name labels of the next ordered name in the zone
    /// * `type_bit_maps` - a bit map of the types that exist at this name
    ///
    /// # Returns
    ///
    /// An NSEC RData for use in a Resource Record
    pub fn new(
        next_domain_name: Name,
        type_bit_maps: impl IntoIterator<Item = RecordType>,
    ) -> Self {
        Self {
            next_domain_name,
            type_bit_maps: RecordTypeSet::new(type_bit_maps),
        }
    }

    /// Constructs a new NSEC RData, this will add the NSEC itself as covered, generally
    ///   correct for NSEC records generated at their own name
    ///
    /// # Arguments
    ///
    /// * `next_domain_name` - the name labels of the next ordered name in the zone
    /// * `type_bit_maps` - a bit map of the types that exist at this name
    ///
    /// # Returns
    ///
    /// An NSEC RData for use in a Resource Record
    pub fn new_cover_self(
        next_domain_name: Name,
        type_bit_maps: impl IntoIterator<Item = RecordType>,
    ) -> Self {
        Self::new(
            next_domain_name,
            type_bit_maps.into_iter().chain([RecordType::NSEC]),
        )
    }

    /// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-4.1.1), DNSSEC Resource Records, March 2005
    ///
    /// ```text
    /// 4.1.1.  The Next Domain Name Field
    ///
    ///    The Next Domain field contains the next owner name (in the canonical
    ///    ordering of the zone) that has authoritative data or contains a
    ///    delegation point NS RRset; see Section 6.1 for an explanation of
    ///    canonical ordering.  The value of the Next Domain Name field in the
    ///    last NSEC record in the zone is the name of the zone apex (the owner
    ///    name of the zone's SOA RR).  This indicates that the owner name of
    ///    the NSEC RR is the last name in the canonical ordering of the zone.
    ///
    ///    A sender MUST NOT use DNS name compression on the Next Domain Name
    ///    field when transmitting an NSEC RR.
    ///
    ///    Owner names of RRsets for which the given zone is not authoritative
    ///    (such as glue records) MUST NOT be listed in the Next Domain Name
    ///    unless at least one authoritative RRset exists at the same owner
    ///    name.
    /// ```
    pub fn next_domain_name(&self) -> &Name {
        &self.next_domain_name
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-4.1.2)
    ///
    /// ```text
    /// 4.1.2.  The Type Bit Maps Field
    ///
    ///    The Type Bit Maps field identifies the RRset types that exist at the
    ///    NSEC RR's owner name.
    ///
    ///    A zone MUST NOT include an NSEC RR for any domain name that only
    ///    holds glue records.
    /// ```
    pub fn type_bit_maps(&self) -> impl Iterator<Item = RecordType> + '_ {
        self.type_bit_maps.iter()
    }

    pub(crate) fn type_set(&self) -> &RecordTypeSet {
        &self.type_bit_maps
    }
}

impl BinEncodable for NSEC {
    /// [RFC 6840](https://tools.ietf.org/html/rfc6840#section-6)
    ///
    /// ```text
    /// 5.1.  Errors in Canonical Form Type Code List
    ///
    ///   When canonicalizing DNS names (for both ordering and signing), DNS
    ///   names in the RDATA section of NSEC resource records are not converted
    ///   to lowercase.  DNS names in the RDATA section of RRSIG resource
    ///   records are converted to lowercase.
    /// ```
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.with_canonical_names(|encoder| {
            self.next_domain_name().emit(encoder)?;
            self.type_bit_maps.emit(encoder)?;

            Ok(())
        })
    }
}

impl<'r> RecordDataDecodable<'r> for NSEC {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        let next_domain_name = Name::read(decoder)?;

        let offset = u16::try_from(decoder.index() - start_idx)
            .map_err(|_| ProtoError::from("decoding offset too large in NSEC"))?;
        let bit_map_len = length
            .checked_sub(offset)
            .map_err(|_| ProtoError::from("invalid rdata length in NSEC"))?;
        let type_bit_maps = RecordTypeSet::read_data(decoder, bit_map_len)?;

        Ok(Self {
            next_domain_name,
            type_bit_maps,
        })
    }
}

impl RecordData for NSEC {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::NSEC(csync)) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::NSEC(csync)) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::NSEC
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::NSEC(self))
    }
}

/// [RFC 4034](https://tools.ietf.org/html/rfc4034#section-4.2), DNSSEC Resource Records, March 2005
///
/// ```text
/// 4.2.  The NSEC RR Presentation Format
///
///    The presentation format of the RDATA portion is as follows:
///
///    The Next Domain Name field is represented as a domain name.
///
///    The Type Bit Maps field is represented as a sequence of RR type
///    mnemonics.  When the mnemonic is not known, the TYPE representation
///    described in [RFC3597], Section 5, MUST be used.
///
/// 4.3.  NSEC RR Example
///
///    The following NSEC RR identifies the RRsets associated with
///    alfa.example.com. and identifies the next authoritative name after
///    alfa.example.com.
///
///    alfa.example.com. 86400 IN NSEC host.example.com. (
///                                    A MX RRSIG NSEC TYPE1234 )
///
///    The first four text fields specify the name, TTL, Class, and RR type
///    (NSEC).  The entry host.example.com. is the next authoritative name
///    after alfa.example.com. in canonical order.  The A, MX, RRSIG, NSEC,
///    and TYPE1234 mnemonics indicate that there are A, MX, RRSIG, NSEC,
///    and TYPE1234 RRsets associated with the name alfa.example.com.
///
///    Assuming that the validator can authenticate this NSEC record, it
///    could be used to prove that beta.example.com does not exist, or to
///    prove that there is no AAAA record associated with alfa.example.com.
///    Authenticated denial of existence is discussed in [RFC4035].
/// ```
impl fmt::Display for NSEC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.next_domain_name)?;

        for ty in self.type_bit_maps.iter() {
            write!(f, " {ty}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test() {
        use crate::rr::RecordType;
        use core::str::FromStr;

        let rdata = NSEC::new(
            Name::from_str("www.example.com.").unwrap(),
            [
                RecordType::A,
                RecordType::AAAA,
                RecordType::DS,
                RecordType::RRSIG,
            ],
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = NSEC::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn rfc4034_example_rdata() {
        // From section 4.3 of RFC 4034
        let bytes = b"\x04host\
        \x07example\
        \x03com\x00\
        \x00\x06\x40\x01\x00\x00\x00\x03\
        \x04\x1b\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x20";
        let rdata = NSEC::new(
            Name::parse("host.example.com.", None).unwrap(),
            [
                RecordType::A,
                RecordType::MX,
                RecordType::RRSIG,
                RecordType::NSEC,
                RecordType::Unknown(1234),
            ],
        );

        let mut buffer = Vec::new();
        let mut encoder = BinEncoder::new(&mut buffer);
        rdata.emit(&mut encoder).expect("Encoding error");
        assert_eq!(encoder.into_bytes(), bytes);

        let mut decoder = BinDecoder::new(bytes);
        let decoded = NSEC::read_data(&mut decoder, Restrict::new(bytes.len() as u16))
            .expect("Decoding error");
        assert_eq!(decoded, rdata);
    }
}
