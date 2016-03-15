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
use std::collections::{HashMap};

use ::serialize::binary::*;
use ::error::*;
use ::rr::{RecordType, RData};
use ::rr::dnssec::Nsec3HashAlgorithm;

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
//
// NSEC3{ hash_algorithm: Nsec3HashAlgorithm, opt_out: bool, iterations: u16, salt: Vec<u8>,
//   next_hashed_owner_name: Vec<u8>, type_bit_maps: Vec<RecordType>},
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> DecodeResult<RData> {
  let start_idx = decoder.index();

  let hash_algorithm = try!(Nsec3HashAlgorithm::from_u8(try!(decoder.read_u8())));
  let flags: u8 = try!(decoder.read_u8());

  if flags & 0b1111_1110 != 0 { return Err(DecodeError::UnrecognizedNsec3Flags(flags)) }
  let opt_out: bool = flags & 0b0000_0001 == 0b0000_0001;
  let iterations: u16 = try!(decoder.read_u16());
  let salt_len: u8 = try!(decoder.read_u8());
  let salt: Vec<u8> = try!(decoder.read_vec(salt_len as usize));
  let hash_len: u8 = try!(decoder.read_u8());
  let next_hashed_owner_name: Vec<u8> = try!(decoder.read_vec(hash_len as usize));

  let bit_map_len = rdata_length as usize - (decoder.index() - start_idx);
  let record_types = try!(decode_type_bit_maps(decoder, bit_map_len));

  Ok(RData::NSEC3{ hash_algorithm: hash_algorithm, opt_out: opt_out, iterations: iterations,
                   salt: salt, next_hashed_owner_name: next_hashed_owner_name,
                   type_bit_maps: record_types })
}

pub fn decode_type_bit_maps(decoder: &mut BinDecoder, bit_map_len: usize) -> DecodeResult<Vec<RecordType>> {
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
    let current_byte = try!(decoder.read_u8());

    state = match state {
      BitMapState::ReadWindow => BitMapState::ReadLen{ window: current_byte },
      BitMapState::ReadLen{ window } => BitMapState::ReadType{ window: window, len: current_byte, left: current_byte },
      BitMapState::ReadType{ window, len, left } => {
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
            let rr_type: u16 = (window as u16) << 8 | low_byte as u16;
            record_types.push(try!(RecordType::from_u16(rr_type)));
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
          BitMapState::ReadType { window: window, len: len, left: left }
        }
      },
    };
  }

  Ok(record_types)
}

enum BitMapState {
  ReadWindow,
  ReadLen{ window: u8 },
  ReadType{ window: u8, len: u8, left: u8 },
}

pub fn emit(encoder: &mut BinEncoder, rdata: &RData) -> EncodeResult {
  if let RData::NSEC3{ hash_algorithm, opt_out, iterations,
                   ref salt, ref next_hashed_owner_name,
                   ref type_bit_maps } = *rdata {
    try!(encoder.emit(hash_algorithm.into()));
    let mut flags: u8 = 0;
    if opt_out { flags |= 0b0000_0001 };
    try!(encoder.emit(flags));
    try!(encoder.emit_u16(iterations));
    try!(encoder.emit(salt.len() as u8));
    try!(encoder.emit_vec(salt));
    try!(encoder.emit(next_hashed_owner_name.len() as u8));
    try!(encoder.emit_vec(next_hashed_owner_name));
    try!(encode_bit_maps(encoder, type_bit_maps));

    Ok(())
  } else {
    panic!("wrong type here {:?}", rdata);
  }
}

pub fn encode_bit_maps(encoder: &mut BinEncoder, type_bit_maps: &[RecordType]) -> EncodeResult {
  let mut hash: HashMap<u8, Vec<u8>> = HashMap::new();

  // collect the bitmaps
  for rr_type in type_bit_maps {
    let code: u16 = (*rr_type).into();
    let window: u8 = (code >> 8) as u8;
    let low: u8 = (code & 0x00FF) as u8;

    let bit_map: &mut Vec<u8> = hash.entry(window).or_insert(Vec::new());
    // len + left is the block in the bitmap, divided by 8 for the bits, + the bit in the current_byte
    let index: u8 = low / 8;
    let bit: u8 = 0b1000_0000 >> (low % 8);

    for _ in 0..((index as usize + 1) - bit_map.len()) {
      bit_map.push(0);
    }

    bit_map[index as usize] |= bit;
  }

  // output bitmaps
  for (window, bitmap) in hash {
    try!(encoder.emit(window));
    // the hashset should never be larger that 255 based on above logic.
    try!(encoder.emit(bitmap.len() as u8));
    for bits in bitmap {
      try!(encoder.emit(bits));
    }
  }

  Ok(())
}

#[test]
pub fn test() {
  let rdata = RData::NSEC3{ hash_algorithm: Nsec3HashAlgorithm::SHA1, opt_out: true, iterations: 2,
                   salt: vec![1,2,3,4,5], next_hashed_owner_name: vec![6,7,8,9,0],
                   type_bit_maps: vec![RecordType::A, RecordType::AAAA, RecordType::DS, RecordType::RRSIG] };

  let mut bytes = Vec::new();
  let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
  assert!(emit(&mut encoder, &rdata).is_ok());
  let bytes = encoder.as_bytes();

  println!("bytes: {:?}", bytes);

  let mut decoder: BinDecoder = BinDecoder::new(bytes);
  let read_rdata = read(&mut decoder, bytes.len() as u16);
  assert!(read_rdata.is_ok(), format!("error decoding: {:?}", read_rdata.unwrap_err()));
  assert_eq!(rdata, read_rdata.unwrap());
}
