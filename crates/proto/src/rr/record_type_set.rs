// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! type bit map helper definitions

use core::fmt;
use core::hash::{Hash, Hasher};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::error::*;
use crate::rr::{RecordDataDecodable, RecordType};
use crate::serialize::binary::*;

/// A collection of record types.
///
/// This represents the "type bit maps" field in various records.
#[derive(Clone)]
pub(crate) struct RecordTypeSet {
    types: BTreeSet<RecordType>,
    original_encoding: Option<Vec<u8>>,
}

impl RecordTypeSet {
    /// Construct a new set of record types.
    pub(crate) fn new(types: impl IntoIterator<Item = RecordType>) -> Self {
        Self {
            types: types.into_iter().collect(),
            original_encoding: None,
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = RecordType> + '_ {
        self.types.iter().copied()
    }

    #[cfg(feature = "__dnssec")]
    pub(crate) fn contains(&self, r#type: RecordType) -> bool {
        self.types.contains(&r#type)
    }
}

impl PartialEq for RecordTypeSet {
    fn eq(&self, other: &Self) -> bool {
        self.types == other.types
    }
}

impl Eq for RecordTypeSet {}

impl Hash for RecordTypeSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.types.hash(state);
    }
}

impl fmt::Debug for RecordTypeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let original_encoding = if self.original_encoding.is_some() {
            &"Some(...)"
        } else {
            &"None"
        };
        f.debug_struct("RecordTypeSet")
            .field("types", &self.types)
            .field("original_encoding", original_encoding)
            .finish()
    }
}

impl BinEncodable for RecordTypeSet {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        if let Some(encoded_bytes) = &self.original_encoding {
            return encoder.emit_vec(encoded_bytes);
        }

        let mut hash: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

        // collect the bitmaps
        for rr_type in self.types.iter() {
            let code = u16::from(*rr_type);
            let window = (code >> 8) as u8;
            let low = (code & 0x00FF) as u8;

            let bit_map = hash.entry(window).or_default();
            // len + left is the block in the bitmap, divided by 8 for the bits, + the bit in the current_byte
            let index = low / 8;
            let bit = 0b1000_0000 >> (low % 8);

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
}

impl RecordDataDecodable<'_> for RecordTypeSet {
    fn read_data(decoder: &mut BinDecoder<'_>, length: Restrict<u16>) -> ProtoResult<Self> {
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
        let mut types = BTreeSet::new();
        let mut state = BitMapReadState::Window;

        // loop through all the bytes in the bitmap
        let bit_map_len = length.unverified();
        let bytes = decoder.read_vec(bit_map_len as usize)?.unverified();
        for current_byte in bytes.iter() {
            state = match state {
                BitMapReadState::Window => BitMapReadState::Len {
                    window: *current_byte,
                },
                BitMapReadState::Len { window } => BitMapReadState::RecordType {
                    window,
                    len: Restrict::new(*current_byte),
                    left: Restrict::new(*current_byte),
                },
                BitMapReadState::RecordType { window, len, left } => {
                    // window is the Window Block # from above
                    // len is the Bitmap Length
                    // current_byte is the Bitmap
                    let mut bit_map = *current_byte;

                    // for all the bits in the current_byte
                    for i in 0..8 {
                        // if the current_bytes most significant bit is set
                        if bit_map & 0b1000_0000 == 0b1000_0000 {
                            // len - left is the block in the bitmap, times 8 for the bits, + the bit in the current_byte
                            let low_byte: u8 = len
                            .checked_sub(left.unverified(/*will fail as param in this call if invalid*/))
                            .checked_mul(8)
                            .checked_add(i)
                            .map_err(|_| "block len or left out of bounds in NSEC(3)")?
                            .unverified(/*any u8 is valid at this point*/);
                            let rr_type: u16 = (u16::from(window) << 8) | u16::from(low_byte);
                            types.insert(RecordType::from(rr_type));
                        }
                        // shift left and look at the next bit
                        bit_map <<= 1;
                    }

                    // move to the next section of the bit_map
                    let left = left
                        .checked_sub(1)
                        .map_err(|_| ProtoError::from("block left out of bounds in NSEC(3)"))?;
                    if left.unverified(/*comparison is safe*/) == 0 {
                        // we've exhausted this Window, move to the next
                        BitMapReadState::Window
                    } else {
                        // continue reading this Window
                        BitMapReadState::RecordType { window, len, left }
                    }
                }
            };
        }

        Ok(Self {
            types,
            original_encoding: Some(bytes),
        })
    }
}

enum BitMapReadState {
    Window,
    Len {
        window: u8,
    },
    RecordType {
        window: u8,
        len: Restrict<u8>,
        left: Restrict<u8>,
    },
}

#[cfg(feature = "serde")]
mod serde {
    use alloc::collections::BTreeSet;

    use serde::{Deserialize, Serialize};

    use super::RecordTypeSet;

    impl<'de> Deserialize<'de> for RecordTypeSet {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Self {
                types: BTreeSet::deserialize(deserializer)?,
                original_encoding: None,
            })
        }
    }

    impl Serialize for RecordTypeSet {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.types.serialize(serializer)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test_encode_decode() {
        let types = RecordTypeSet::new([RecordType::A, RecordType::NS]);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        types.emit(&mut encoder).expect("Encoding error");
        let bytes = encoder.into_bytes();

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_bit_map =
            RecordTypeSet::read_data(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(types, read_bit_map);
    }
}
