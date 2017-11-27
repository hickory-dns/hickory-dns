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

//! hashed negative cache proof for non-existence

use std::collections::BTreeMap;

use serialize::binary::*;
use error::*;
use rr::RecordType;
use rr::dnssec::Nsec3HashAlgorithm;

/// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3)
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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NSEC3 {
    hash_algorithm: Nsec3HashAlgorithm,
    opt_out: bool,
    iterations: u16,
    salt: Vec<u8>,
    next_hashed_owner_name: Vec<u8>,
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
    ) -> NSEC3 {
        NSEC3 {
            hash_algorithm: hash_algorithm,
            opt_out: opt_out,
            iterations: iterations,
            salt: salt,
            next_hashed_owner_name: next_hashed_owner_name,
            type_bit_maps: type_bit_maps,
        }
    }

    /// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3.1.1)
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

    /// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3.1.2)
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

    /// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3.1.3)
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

    /// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3.1.5)
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

    /// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3.1.7)
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

    /// [RFC 5155, NSEC3, March 2008](https://tools.ietf.org/html/rfc5155#section-3.1.8)
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
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> ProtoResult<NSEC3> {
    let start_idx = decoder.index();

    let hash_algorithm = Nsec3HashAlgorithm::from_u8(decoder.read_u8()?)?;
    let flags: u8 = decoder.read_u8()?;

    if flags & 0b1111_1110 != 0 {
        return Err(ProtoErrorKind::UnrecognizedNsec3Flags(flags).into());
    }
    let opt_out: bool = flags & 0b0000_0001 == 0b0000_0001;
    let iterations: u16 = decoder.read_u16()?;
    let salt_len: u8 = decoder.read_u8()?;
    let salt: Vec<u8> = decoder.read_vec(salt_len as usize)?;
    let hash_len: u8 = decoder.read_u8()?;
    let next_hashed_owner_name: Vec<u8> = decoder.read_vec(hash_len as usize)?;

    let bit_map_len = rdata_length as usize - (decoder.index() - start_idx);
    let record_types = decode_type_bit_maps(decoder, bit_map_len)?;

    Ok(NSEC3::new(
        hash_algorithm,
        opt_out,
        iterations,
        salt,
        next_hashed_owner_name,
        record_types,
    ))
}

/// Decodes the array of RecordTypes covered by this NSEC record
///
/// # Arguments
///
/// * `decoder` - decoder to read from
/// * `bit_map_len` - the number bytes in the bit map
///
/// # Returns
///
/// The Array of covered types
pub fn decode_type_bit_maps(
    decoder: &mut BinDecoder,
    bit_map_len: usize,
) -> ProtoResult<Vec<RecordType>> {
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
    let mut record_types: Vec<RecordType> = Vec::new();
    let mut state: BitMapState = BitMapState::ReadWindow;

    // loop through all the bytes in the bitmap
    for _ in 0..bit_map_len {
        let current_byte = decoder.read_u8()?;

        state = match state {
            BitMapState::ReadWindow => BitMapState::ReadLen {
                window: current_byte,
            },
            BitMapState::ReadLen { window } => BitMapState::ReadType {
                window: window,
                len: current_byte,
                left: current_byte,
            },
            BitMapState::ReadType { window, len, left } => {
                // window is the Window Block # from above
                // len is the Bitmap Length
                // current_byte is the Bitmap
                let mut bit_map = current_byte;

                // for all the bits in the current_byte
                for i in 0..8 {
                    // if the current_bytes most significant bit is set
                    if bit_map & 0b1000_0000 == 0b1000_0000 {
                        // len - left is the block in the bitmap, times 8 for the bits, + the bit in the current_byte
                        let low_byte = ((len - left) * 8) + i;
                        let rr_type: u16 = (u16::from(window) << 8) | u16::from(low_byte);
                        record_types.push(RecordType::from(rr_type));
                    }
                    // shift left and look at the next bit
                    bit_map <<= 1;
                }

                // move to the next section of the bit_map
                let left = left - 1;
                if left == 0 {
                    // we've exhausted this Window, move to the next
                    BitMapState::ReadWindow
                } else {
                    // continue reading this Window
                    BitMapState::ReadType {
                        window: window,
                        len: len,
                        left: left,
                    }
                }
            }
        };
    }

    Ok(record_types)
}

enum BitMapState {
    ReadWindow,
    ReadLen { window: u8 },
    ReadType { window: u8, len: u8, left: u8 },
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, rdata: &NSEC3) -> ProtoResult<()> {
    encoder.emit(rdata.hash_algorithm().into())?;
    let mut flags: u8 = 0;
    if rdata.opt_out() {
        flags |= 0b0000_0001
    };
    encoder.emit(flags)?;
    encoder.emit_u16(rdata.iterations())?;
    encoder.emit(rdata.salt().len() as u8)?;
    encoder.emit_vec(rdata.salt())?;
    encoder.emit(rdata.next_hashed_owner_name().len() as u8)?;
    encoder.emit_vec(rdata.next_hashed_owner_name())?;
    encode_bit_maps(encoder, rdata.type_bit_maps())?;

    Ok(())
}

/// Encode the bit map
///
/// # Arguments
///
/// * `encoder` - the encoder to write to
/// * `type_bit_maps` - types to encode into the bitmap
pub fn encode_bit_maps(encoder: &mut BinEncoder, type_bit_maps: &[RecordType]) -> ProtoResult<()> {
    let mut hash: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut type_bit_maps = type_bit_maps.to_vec();
    type_bit_maps.sort();

    // collect the bitmaps
    for rr_type in type_bit_maps {
        let code: u16 = (rr_type).into();
        let window: u8 = (code >> 8) as u8;
        let low: u8 = (code & 0x00FF) as u8;

        let bit_map: &mut Vec<u8> = hash.entry(window).or_insert_with(Vec::new);
        // len + left is the block in the bitmap, divided by 8 for the bits, + the bit in the current_byte
        let index: u8 = low / 8;
        let bit: u8 = 0b1000_0000 >> (low % 8);

        // adding necessary space to the vector
        if bit_map.len() < (index as usize + 1) {
            bit_map.resize(index as usize + 1, 0_u8);
        }

        bit_map[index as usize] |= bit;
    }

    // output bitmaps
    for (window, bitmap) in hash {
        encoder.emit(window)?;
        // the hashset should never be larger that 255 based on above logic.
        encoder.emit(bitmap.len() as u8)?;
        for bits in bitmap {
            encoder.emit(bits)?;
        }
    }

    Ok(())
}

#[test]
pub fn test() {
    use rr::dnssec::rdata::DNSSECRecordType;

    let rdata = NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        true,
        2,
        vec![1, 2, 3, 4, 5],
        vec![6, 7, 8, 9, 0],
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
    let read_rdata = read(&mut decoder, bytes.len() as u16);
    assert!(
        read_rdata.is_ok(),
        format!("error decoding: {:?}", read_rdata.unwrap_err())
    );
    assert_eq!(rdata, read_rdata.unwrap());
}

#[test]
pub fn test_dups() {
    use rr::dnssec::rdata::DNSSECRecordType;

    let rdata_with_dups = NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        true,
        2,
        vec![1, 2, 3, 4, 5],
        vec![6, 7, 8, 9, 0],
        vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::DNSSEC(DNSSECRecordType::DS),
            RecordType::AAAA,
            RecordType::DNSSEC(DNSSECRecordType::RRSIG),
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
            RecordType::DNSSEC(DNSSECRecordType::DS),
            RecordType::DNSSEC(DNSSECRecordType::RRSIG),
        ],
    );

    let mut bytes = Vec::new();
    let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
    assert!(emit(&mut encoder, &rdata_with_dups).is_ok());
    let bytes = encoder.into_bytes();

    println!("bytes: {:?}", bytes);

    let mut decoder: BinDecoder = BinDecoder::new(bytes);
    let read_rdata = read(&mut decoder, bytes.len() as u16);
    assert!(
        read_rdata.is_ok(),
        format!("error decoding: {:?}", read_rdata.unwrap_err())
    );
    assert_eq!(rdata_wo, read_rdata.unwrap());
}
