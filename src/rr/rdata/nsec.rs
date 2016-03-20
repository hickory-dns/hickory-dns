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
use ::serialize::binary::*;
use ::error::*;
use ::rr::{RData, Name};
use ::rr::rdata::nsec3;

// RFC 4034                DNSSEC Resource Records               March 2005
//
// 4.1.  NSEC RDATA Wire Format
//
//    The RDATA of the NSEC RR is as shown below:
//
//                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                      Next Domain Name                         /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                       Type Bit Maps                           /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// 4.1.1.  The Next Domain Name Field
//
//    The Next Domain field contains the next owner name (in the canonical
//    ordering of the zone) that has authoritative data or contains a
//    delegation point NS RRset; see Section 6.1 for an explanation of
//    canonical ordering.  The value of the Next Domain Name field in the
//    last NSEC record in the zone is the name of the zone apex (the owner
//    name of the zone's SOA RR).  This indicates that the owner name of
//    the NSEC RR is the last name in the canonical ordering of the zone.
//
//    A sender MUST NOT use DNS name compression on the Next Domain Name
//    field when transmitting an NSEC RR.
//
//    Owner names of RRsets for which the given zone is not authoritative
//    (such as glue records) MUST NOT be listed in the Next Domain Name
//    unless at least one authoritative RRset exists at the same owner
//    name.
//
// 4.1.2.  The Type Bit Maps Field
//
//    The Type Bit Maps field identifies the RRset types that exist at the
//    NSEC RR's owner name.
//
//    The RR type space is split into 256 window blocks, each representing
//    the low-order 8 bits of the 16-bit RR type space.  Each block that
//    has at least one active RR type is encoded using a single octet
//    window number (from 0 to 255), a single octet bitmap length (from 1
//    to 32) indicating the number of octets used for the window block's
//    bitmap, and up to 32 octets (256 bits) of bitmap.
//
//    Blocks are present in the NSEC RR RDATA in increasing numerical
//    order.
//
//       Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+
//
//       where "|" denotes concatenation.
//
//    Each bitmap encodes the low-order 8 bits of RR types within the
//    window block, in network bit order.  The first bit is bit 0.  For
//    window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
//    to RR type 2 (NS), and so forth.  For window block 1, bit 1
//    corresponds to RR type 257, and bit 2 to RR type 258.  If a bit is
//    set, it indicates that an RRset of that type is present for the NSEC
//    RR's owner name.  If a bit is clear, it indicates that no RRset of
//    that type is present for the NSEC RR's owner name.
//
//    Bits representing pseudo-types MUST be clear, as they do not appear
//    in zone data.  If encountered, they MUST be ignored upon being read.
//
//    Blocks with no types present MUST NOT be included.  Trailing zero
//    octets in the bitmap MUST be omitted.  The length of each block's
//    bitmap is determined by the type code with the largest numerical
//    value, within that block, among the set of RR types present at the
//    NSEC RR's owner name.  Trailing zero octets not specified MUST be
//    interpreted as zero octets.
//
//    The bitmap for the NSEC RR at a delegation point requires special
//    attention.  Bits corresponding to the delegation NS RRset and the RR
//    types for which the parent zone has authoritative data MUST be set;
//    bits corresponding to any non-NS RRset for which the parent is not
//    authoritative MUST be clear.
//
//    A zone MUST NOT include an NSEC RR for any domain name that only
//    holds glue records.
//
// 4.1.3.  Inclusion of Wildcard Names in NSEC RDATA
//
//    If a wildcard owner name appears in a zone, the wildcard label ("*")
//    is treated as a literal symbol and is treated the same as any other
//    owner name for the purposes of generating NSEC RRs.  Wildcard owner
//    names appear in the Next Domain Name field without any wildcard
//    expansion.  [RFC4035] describes the impact of wildcards on
//    authenticated denial of existence.
//
//   NSEC { next_domain_name: Name, type_bit_maps: Vec<RecordType> },
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> DecodeResult<RData> {
  let start_idx = decoder.index();

  let next_domain_name = try!(Name::read(decoder));

  let bit_map_len = rdata_length as usize - (decoder.index() - start_idx);
  let record_types = try!(nsec3::decode_type_bit_maps(decoder, bit_map_len));

  Ok(RData::NSEC{ next_domain_name: next_domain_name, type_bit_maps: record_types })
}

pub fn emit(encoder: &mut BinEncoder, rdata: &RData) -> EncodeResult {
  if let RData::NSEC{ ref next_domain_name, ref type_bit_maps } = *rdata {
    let is_canonical_names = encoder.is_canonical_names();
    encoder.set_canonical_names(true);
    try!(next_domain_name.emit(encoder));
    try!(nsec3::encode_bit_maps(encoder, type_bit_maps));
    encoder.set_canonical_names(is_canonical_names);

    Ok(())
  } else {
    panic!("wrong type here {:?}", rdata);
  }
}

#[test]
pub fn test() {
  use ::rr::RecordType;

  let rdata = RData::NSEC{ next_domain_name: Name::new().label("www").label("example").label("com"),
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
