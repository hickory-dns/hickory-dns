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
use std::io::Write;

use openssl::crypto::hash::{Hasher, Type};
use openssl::crypto::pkey::{PKey, Role};

use ::op::Message;
use ::rr::dnssec::Algorithm;
use ::rr::Record;
use ::rr::domain::Name;
use ::serialize::binary::{BinEncoder, BinSerializable};

pub struct Signer {
  algorithm: Algorithm,
  pkey: PKey,
  signer_name: Name,
}

impl Signer {
  pub fn new(algorithm: Algorithm, pkey: PKey, signer_name: Name) -> Self {
    Signer{ algorithm: algorithm, pkey: pkey, signer_name: signer_name }
  }

  pub fn get_algorithm(&self) -> Algorithm { self.algorithm }
  pub fn get_signer_name(&self) -> &Name { &self.signer_name }

  // RFC 2535                DNS Security Extensions               March 1999
  //
  // 4.1.6 Key Tag Field
  //
  //  The "key Tag" is a two octet quantity that is used to efficiently
  //  select between multiple keys which may be applicable and thus check
  //  that a public key about to be used for the computationally expensive
  //  effort to check the signature is possibly valid.  For algorithm 1
  //  (MD5/RSA) as defined in [RFC 2537], it is the next to the bottom two
  //  octets of the public key modulus needed to decode the signature
  //  field.  That is to say, the most significant 16 of the least
  //  significant 24 bits of the modulus in network (big endian) order. For
  //  all other algorithms, including private algorithms, it is calculated
  //  as a simple checksum of the KEY RR as described in Appendix C.
  //
  // Appendix C: Key Tag Calculation
  //
  //  The key tag field in the SIG RR is just a means of more efficiently
  //  selecting the correct KEY RR to use when there is more than one KEY
  //  RR candidate available, for example, in verifying a signature.  It is
  //  possible for more than one candidate key to have the same tag, in
  //  which case each must be tried until one works or all fail.  The
  //  following reference implementation of how to calculate the Key Tag,
  //  for all algorithms other than algorithm 1, is in ANSI C.  It is coded
  //  for clarity, not efficiency.  (See section 4.1.6 for how to determine
  //  the Key Tag of an algorithm 1 key.)
  //
  //  /* assumes int is at least 16 bits
  //     first byte of the key tag is the most significant byte of return
  //     value
  //     second byte of the key tag is the least significant byte of
  //     return value
  //     */
  //
  //  int keytag (
  //
  //          unsigned char key[],  /* the RDATA part of the KEY RR */
  //          unsigned int keysize, /* the RDLENGTH */
  //          )
  //  {
  //  long int    ac;    /* assumed to be 32 bits or larger */
  //
  //  for ( ac = 0, i = 0; i < keysize; ++i )
  //      ac += (i&1) ? key[i] : key[i]<<8;
  //  ac += (ac>>16) & 0xFFFF;
  //  return ac & 0xFFFF;
  //  }
  pub fn calculate_key_tag(&self) -> u16 {
    let mut ac: usize = 0;

    // TODO This might need to be the RAW key, as opposed to the DER formatted public key
    //  would need to extract the RAW public key: https://en.wikipedia.org/wiki/X.690#DER_encoding

    // TODO use insert i with known sizes for optimized loop unrolling.
    for (i,k) in self.pkey.save_pub().iter().enumerate() {
      ac += if i & 0x0001 == 0x0001 { *k as usize } else { (*k as usize) << 8 };
    }

    ac += (ac >> 16 ) & 0xFFFF;
    return (ac & 0xFFFF) as u16; // this is unnecessary, no?
  }

  fn hash_message(&self, message: &Message) -> Vec<u8> {
    let mut hasher = Hasher::new(self.algorithm.get_hash_type());

    // TODO: should perform the serialization and sign block by block to reduce the max memory
    //  usage, though at 4k max, this is probably unnecessary... For AXFR and large zones, it's
    //  more important
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    {
      let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
      message.emit(&mut encoder).unwrap(); // coding error if this panics (i think?)
    }

    hasher.write_all(&buf);
    hasher.finish()
  }

  /// 4.1.8.1 Calculating Transaction and Request SIGs
  ///
  ///  A response message from a security aware server may optionally
  ///  contain a special SIG at the end of the additional information
  ///  section to authenticate the transaction.
  ///
  ///  This SIG has a "type covered" field of zero, which is not a valid RR
  ///  type.  It is calculated by using a "data" (see Section 4.1.8) of the
  ///  entire preceding DNS reply message, including DNS header but not the
  ///  IP header and before the reply RR counts have been adjusted for the
  ///  inclusion of any transaction SIG, concatenated with the entire DNS
  ///  query message that produced this response, including the query's DNS
  ///  header and any request SIGs but not its IP header.  That is
  ///
  ///     data = full response (less transaction SIG) | full query
  ///
  ///  Verification of the transaction SIG (which is signed by the server
  ///  host key, not the zone key) by the requesting resolver shows that the
  ///  query and response were not tampered with in transit, that the
  ///  response corresponds to the intended query, and that the response
  ///  comes from the queried server.
  ///
  ///  A DNS request may be optionally signed by including one or more SIGs
  ///  at the end of the query. Such SIGs are identified by having a "type
  ///  covered" field of zero. They sign the preceding DNS request message
  ///  including DNS header but not including the IP header or any request
  ///  SIGs at the end and before the request RR counts have been adjusted
  ///  for the inclusions of any request SIG(s).
  ///
  ///  WARNING: Request SIGs are unnecessary for any currently defined
  ///  request other than update [RFC 2136, 2137] and will cause some old
  ///  DNS servers to give an error return or ignore a query.  However, such
  ///  SIGs may in the future be needed for other requests.
  ///
  ///  Except where needed to authenticate an update or similar privileged
  ///  request, servers are not required to check request SIGs.
  ///  ---
  ///
  /// NOTE: In classic RFC style, this is unclear, it implies that each SIG record is not included in
  ///  the Additional record count, but this makes it more difficult to process and calculate more
  ///  than one SIG0 record. Annoyingly, it means that the Header is signed with different material
  ///  (i.e. additional record count - #SIG0 records), so the exact header sent is NOT the header
  ///  being verified.
  ///
  ///  ---
  pub fn sign_message(&self, message: &Message) -> Vec<u8> {
    assert!(self.pkey.can(Role::Sign)); // this is bad code, not expected in regular runtime
    let hash = self.hash_message(message);
    self.pkey.sign_with_hash(&hash, self.algorithm.get_hash_type())
  }
}

#[test]
fn test_calculate_key_tag() {
  let mut pkey = PKey::new();
  pkey.gen(512);
  println!("pkey: {:?}", pkey.save_pub());
  let signer = Signer::new(Algorithm::RSASHA256, pkey, Name::root());
  let key_tag = signer.calculate_key_tag();

  println!("key_tag: {}", key_tag);
  assert!(key_tag > 0);
}
