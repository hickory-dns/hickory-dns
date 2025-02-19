// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! NSEC record types

use alloc::{fmt, string::ToString, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    dnssec::Nsec3HashAlgorithm,
    error::{ProtoError, ProtoErrorKind, ProtoResult},
    rr::{RData, RecordData, RecordDataDecodable, RecordType, domain::Label, type_bit_map::*},
    serialize::binary::*,
};

use super::DNSSECRData;

/// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3), NSEC3, March 2008
///
/// ```text
/// 3.  The NSEC3 Resource Record
///
///    The NSEC3 Resource Record (RR) provides authenticated denial of
///    existence for DNS Resource Record Sets.
///
///    The NSEC3 RR lists RR types present at the original owner name of the
///    NSEC3 RR.  It includes the next hashed owner name in the hash order
///    of the zone.  The complete set of NSEC3 RRs in a zone indicates which
///    RRSets exist for the original owner name of the RR and form a chain
///    of hashed owner names in the zone.  This information is used to
///    provide authenticated denial of existence for DNS data.  To provide
///    protection against zone enumeration, the owner names used in the
///    NSEC3 RR are cryptographic hashes of the original owner name
///    prepended as a single label to the name of the zone.  The NSEC3 RR
///    indicates which hash function is used to construct the hash, which
///    salt is used, and how many iterations of the hash function are
///    performed over the original owner name.  The hashing technique is
///    described fully in Section 5.
///
///    Hashed owner names of unsigned delegations may be excluded from the
///    chain.  An NSEC3 RR whose span covers the hash of an owner name or
///    "next closer" name of an unsigned delegation is referred to as an
///    Opt-Out NSEC3 RR and is indicated by the presence of a flag.
///
///    The owner name for the NSEC3 RR is the base32 encoding of the hashed
///    owner name prepended as a single label to the name of the zone.
///
///    The type value for the NSEC3 RR is 50.
///
///    The NSEC3 RR RDATA format is class independent and is described
///    below.
///
///    The class MUST be the same as the class of the original owner name.
///
///    The NSEC3 RR SHOULD have the same TTL value as the SOA minimum TTL
///    field.  This is in the spirit of negative caching [RFC2308].
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
/// ```
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NSEC3 {
    hash_algorithm: Nsec3HashAlgorithm,
    opt_out: bool,
    iterations: u16,
    salt: Vec<u8>,
    next_hashed_owner_name: Vec<u8>,
    /// The next hashed owner name, in base32-encoded form. If the next hashed owner name field is
    /// too long, this may be `None` instead.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    next_hashed_owner_name_base32: Option<Label>,
    type_bit_maps: Vec<RecordType>,
}

impl NSEC3 {
    /// Constructs a new NSEC3 record
    pub fn new(
        hash_algorithm: Nsec3HashAlgorithm,
        opt_out: bool,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner_name: Vec<u8>,
        type_bit_maps: Vec<RecordType>,
    ) -> Self {
        let next_hashed_owner_name_base32 =
            Label::from_ascii(&data_encoding::BASE32_DNSSEC.encode(&next_hashed_owner_name)).ok();
        Self {
            hash_algorithm,
            opt_out,
            iterations,
            salt,
            next_hashed_owner_name,
            next_hashed_owner_name_base32,
            type_bit_maps,
        }
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.1.1), NSEC3, March 2008
    ///
    /// ```text
    /// 3.1.1.  Hash Algorithm
    ///
    ///    The Hash Algorithm field identifies the cryptographic hash algorithm
    ///    used to construct the hash-value.
    ///
    ///    The values for this field are defined in the NSEC3 hash algorithm
    ///    registry defined in Section 11.
    /// ```
    pub fn hash_algorithm(&self) -> Nsec3HashAlgorithm {
        self.hash_algorithm
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.1.2), NSEC3, March 2008
    ///
    /// ```text
    /// 3.1.2.  Flags
    ///
    ///    The Flags field contains 8 one-bit flags that can be used to indicate
    ///    different processing.  All undefined flags must be zero.  The only
    ///    flag defined by this specification is the Opt-Out flag.
    ///
    /// 3.1.2.1.  Opt-Out Flag
    ///
    ///    If the Opt-Out flag is set, the NSEC3 record covers zero or more
    ///    unsigned delegations.
    ///
    ///    If the Opt-Out flag is clear, the NSEC3 record covers zero unsigned
    ///    delegations.
    ///
    ///    The Opt-Out Flag indicates whether this NSEC3 RR may cover unsigned
    ///    delegations.  It is the least significant bit in the Flags field.
    ///    See Section 6 for details about the use of this flag.
    /// ```
    pub fn opt_out(&self) -> bool {
        self.opt_out
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.1.3), NSEC3, March 2008
    ///
    /// ```text
    /// 3.1.3.  Iterations
    ///
    ///    The Iterations field defines the number of additional times the hash
    ///    function has been performed.  More iterations result in greater
    ///    resiliency of the hash value against dictionary attacks, but at a
    ///    higher computational cost for both the server and resolver.  See
    ///    Section 5 for details of the use of this field, and Section 10.3 for
    ///    limitations on the value.
    /// ```
    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.1.5), NSEC3, March 2008
    ///
    /// ```text
    /// 3.1.5.  Salt
    ///
    ///    The Salt field is appended to the original owner name before hashing
    ///    in order to defend against pre-calculated dictionary attacks.  See
    ///    Section 5 for details on how the salt is used.
    /// ```
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.1.7), NSEC3, March 2008
    ///
    /// ```text
    /// 3.1.7.  Next Hashed Owner Name
    ///
    ///  The Next Hashed Owner Name field contains the next hashed owner name
    ///  in hash order.  This value is in binary format.  Given the ordered
    ///  set of all hashed owner names, the Next Hashed Owner Name field
    ///  contains the hash of an owner name that immediately follows the owner
    ///  name of the given NSEC3 RR.  The value of the Next Hashed Owner Name
    ///  field in the last NSEC3 RR in the zone is the same as the hashed
    ///  owner name of the first NSEC3 RR in the zone in hash order.  Note
    ///  that, unlike the owner name of the NSEC3 RR, the value of this field
    ///  does not contain the appended zone name.
    /// ```
    pub fn next_hashed_owner_name(&self) -> &[u8] {
        &self.next_hashed_owner_name
    }

    /// Returns the base32-encoded form of the next hashed owner name.
    ///
    /// This may return `None` if the next hashed owner name is too long.
    pub fn next_hashed_owner_name_base32(&self) -> Option<&Label> {
        self.next_hashed_owner_name_base32.as_ref()
    }

    /// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.1.8), NSEC3, March 2008
    ///
    /// ```text
    /// 3.1.8.  Type Bit Maps
    ///
    ///  The Type Bit Maps field identifies the RRSet types that exist at the
    ///  original owner name of the NSEC3 RR.
    /// ```
    pub fn type_bit_maps(&self) -> &[RecordType] {
        &self.type_bit_maps
    }

    /// Flags for encoding
    pub fn flags(&self) -> u8 {
        let mut flags: u8 = 0;
        if self.opt_out {
            flags |= 0b0000_0001
        };
        flags
    }
}

impl BinEncodable for NSEC3 {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit(self.hash_algorithm().into())?;
        encoder.emit(self.flags())?;
        encoder.emit_u16(self.iterations())?;
        encoder.emit(self.salt().len() as u8)?;
        encoder.emit_vec(self.salt())?;
        encoder.emit(self.next_hashed_owner_name().len() as u8)?;
        encoder.emit_vec(self.next_hashed_owner_name())?;
        encode_type_bit_maps(encoder, self.type_bit_maps())?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for NSEC3 {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let start_idx = decoder.index();

        let hash_algorithm = Nsec3HashAlgorithm::from_u8(
            decoder.read_u8()?.unverified(/*Algorithm verified as safe*/),
        )?;
        let flags: u8 = decoder
            .read_u8()?
            .verify_unwrap(|flags| flags & 0b1111_1110 == 0)
            .map_err(|flags| ProtoError::from(ProtoErrorKind::UnrecognizedNsec3Flags(flags)))?;

        let opt_out: bool = flags & 0b0000_0001 == 0b0000_0001;
        let iterations: u16 = decoder.read_u16()?.unverified(/*valid as any u16*/);

        // read the salt
        let salt_len = decoder.read_u8()?.map(|u| u as usize);
        let salt_len_max = length
            .map(|u| u as usize)
            .checked_sub(decoder.index() - start_idx)
            .map_err(|_| "invalid rdata for salt_len_max")?;
        let salt_len = salt_len
            .verify_unwrap(|salt_len| {
                *salt_len <= salt_len_max.unverified(/*safe in comparison usage*/)
            })
            .map_err(|_| ProtoError::from("salt_len exceeds buffer length"))?;
        let salt: Vec<u8> =
            decoder.read_vec(salt_len)?.unverified(/*salt is any valid array of bytes*/);

        // read the hashed_owner_name
        let hash_len = decoder.read_u8()?.map(|u| u as usize);
        let hash_len_max = length
            .map(|u| u as usize)
            .checked_sub(decoder.index() - start_idx)
            .map_err(|_| "invalid rdata for hash_len_max")?;
        let hash_len = hash_len
            .verify_unwrap(|hash_len| {
                *hash_len <= hash_len_max.unverified(/*safe in comparison usage*/)
            })
            .map_err(|_| ProtoError::from("hash_len exceeds buffer length"))?;
        let next_hashed_owner_name: Vec<u8> =
            decoder.read_vec(hash_len)?.unverified(/*will fail in usage if invalid*/);

        // read the bitmap
        let bit_map_len = length
            .map(|u| u as usize)
            .checked_sub(decoder.index() - start_idx)
            .map_err(|_| "invalid rdata length in NSEC3")?;
        let record_types = decode_type_bit_maps(decoder, bit_map_len)?;

        Ok(Self::new(
            hash_algorithm,
            opt_out,
            iterations,
            salt,
            next_hashed_owner_name,
            record_types,
        ))
    }
}

impl RecordData for NSEC3 {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::DNSSEC(DNSSECRData::NSEC3(csync)) => Ok(csync),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::DNSSEC(DNSSECRData::NSEC3(csync)) => Some(csync),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::NSEC3
    }

    fn into_rdata(self) -> RData {
        RData::DNSSEC(DNSSECRData::NSEC3(self))
    }
}

/// [RFC 5155](https://tools.ietf.org/html/rfc5155#section-3.3), NSEC3, March 2008
///
/// ```text
/// 3.3.  Presentation Format
///
///    The presentation format of the RDATA portion is as follows:
///
///    o  The Hash Algorithm field is represented as an unsigned decimal
///       integer.  The value has a maximum of 255.
///
///    o  The Flags field is represented as an unsigned decimal integer.
///       The value has a maximum of 255.
///
///    o  The Iterations field is represented as an unsigned decimal
///       integer.  The value is between 0 and 65535, inclusive.
///
///    o  The Salt Length field is not represented.
///
///    o  The Salt field is represented as a sequence of case-insensitive
///       hexadecimal digits.  Whitespace is not allowed within the
///       sequence.  The Salt field is represented as "-" (without the
///       quotes) when the Salt Length field has a value of 0.
///
///    o  The Hash Length field is not represented.
///
///    o  The Next Hashed Owner Name field is represented as an unpadded
///       sequence of case-insensitive base32 digits, without whitespace.
///
///    o  The Type Bit Maps field is represented as a sequence of RR type
///       mnemonics.  When the mnemonic is not known, the TYPE
///       representation as described in Section 5 of [RFC3597] MUST be
///       used.
/// ```
impl fmt::Display for NSEC3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let salt = if self.salt.is_empty() {
            "-".to_string()
        } else {
            data_encoding::HEXUPPER_PERMISSIVE.encode(&self.salt)
        };

        write!(
            f,
            "{alg} {flags} {iterations} {salt} {owner}",
            alg = u8::from(self.hash_algorithm),
            flags = self.flags(),
            iterations = self.iterations,
            salt = salt,
            owner = data_encoding::BASE32_DNSSEC.encode(&self.next_hashed_owner_name)
        )?;

        for ty in &self.type_bit_maps {
            write!(f, " {ty}")?;
        }

        Ok(())
    }
}

/// Helper struct used in deserialization of [`NSEC3`].
///
/// This struct excludes the `next_hashed_owner_name_base32` field, which is calculated from
/// `next_hashed_owner_name`. Deserialization of `NSEC3` first uses the automatically generated
/// `Deserialize` implementation provided by this struct, and then uses the [`NSEC3::new`]
/// constructor. Deriving `Deserialize` on `NSEC3` directly would have broken the invariant
/// relating `next_hashed_owner_name` and `next_hashed_owner_name_base32`.
#[cfg(feature = "serde")]
#[derive(Deserialize)]
#[serde(rename = "NSEC3")]
struct NSEC3Serde {
    hash_algorithm: Nsec3HashAlgorithm,
    opt_out: bool,
    iterations: u16,
    salt: Vec<u8>,
    next_hashed_owner_name: Vec<u8>,
    type_bit_maps: Vec<RecordType>,
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for NSEC3 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let NSEC3Serde {
            hash_algorithm,
            opt_out,
            iterations,
            salt,
            next_hashed_owner_name,
            type_bit_maps,
        } = NSEC3Serde::deserialize(deserializer)?;
        Ok(Self::new(
            hash_algorithm,
            opt_out,
            iterations,
            salt,
            next_hashed_owner_name,
            type_bit_maps,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use std::println;

    use super::*;
    use crate::dnssec::rdata::RecordType;

    #[test]
    fn test() {
        let rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            true,
            2,
            vec![1, 2, 3, 4, 5],
            vec![6, 7, 8, 9, 0],
            vec![
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
        let read_rdata = NSEC3::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_dups() {
        let rdata_with_dups = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            true,
            2,
            vec![1, 2, 3, 4, 5],
            vec![6, 7, 8, 9, 0],
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::DS,
                RecordType::AAAA,
                RecordType::RRSIG,
            ],
        );

        let rdata_wo = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            true,
            2,
            vec![1, 2, 3, 4, 5],
            vec![6, 7, 8, 9, 0],
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::DS,
                RecordType::RRSIG,
            ],
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata_with_dups.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = NSEC3::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata_wo, read_rdata);
    }
}
