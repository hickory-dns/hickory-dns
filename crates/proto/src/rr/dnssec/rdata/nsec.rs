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

//! negative cache proof for non-existence

use super::nsec3;
use crate::error::*;
use crate::rr::dnssec::rdata::DNSSECRecordType;
use crate::rr::{Name, RecordType};
use crate::serialize::binary::*;

/// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-4)
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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NSEC {
    next_domain_name: Name,
    type_bit_maps: Vec<RecordType>,
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
    pub fn new(next_domain_name: Name, type_bit_maps: Vec<RecordType>) -> NSEC {
        NSEC {
            next_domain_name,
            type_bit_maps,
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
    pub fn new_cover_self(next_domain_name: Name, mut type_bit_maps: Vec<RecordType>) -> NSEC {
        type_bit_maps.push(RecordType::DNSSEC(DNSSECRecordType::NSEC));

        Self::new(next_domain_name, type_bit_maps)
    }

    /// [RFC 4034, DNSSEC Resource Records, March 2005](https://tools.ietf.org/html/rfc4034#section-4.1.1)
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
    pub fn type_bit_maps(&self) -> &[RecordType] {
        &self.type_bit_maps
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: Restrict<u16>) -> ProtoResult<NSEC> {
    let start_idx = decoder.index();

    let next_domain_name = Name::read(decoder)?;

    let bit_map_len = rdata_length
        .map(|u| u as usize)
        .checked_sub(decoder.index() - start_idx)
        .map_err(|_| ProtoError::from("invalid rdata length in NSEC"))?;
    let record_types = nsec3::decode_type_bit_maps(decoder, bit_map_len)?;

    Ok(NSEC::new(next_domain_name, record_types))
}

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
pub fn emit(encoder: &mut BinEncoder, rdata: &NSEC) -> ProtoResult<()> {
    encoder.with_canonical_names(|encoder| {
        rdata.next_domain_name().emit(encoder)?;
        nsec3::encode_bit_maps(encoder, rdata.type_bit_maps())
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    pub fn test() {
        use crate::rr::dnssec::rdata::DNSSECRecordType;
        use crate::rr::RecordType;
        use std::str::FromStr;

        let rdata = NSEC::new(
            Name::from_str("www.example.com").unwrap(),
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::DNSSEC(DNSSECRecordType::DS),
                RecordType::DNSSEC(DNSSECRecordType::RRSIG),
            ],
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = read(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
