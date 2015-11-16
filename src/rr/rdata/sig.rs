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
use ::serialize::txt::*;
use ::serialize::binary::*;
use ::error::*;
use ::rr::record_data::RData;
use ::rr::domain::Name;
use ::rr::dnssec::Algorithm;

// RFC 2535 & 2931   DNS Security Extensions               March 1999
//
// NOTE: RFC 2535 was obsoleted with 4034+, with the exception of the
//  usage for UPDATE, which is what this implementation is for.
//
// 4.1 SIG RDATA Format
//
//  The RDATA portion of a SIG RR is as shown below.  The integrity of
//  the RDATA information is protected by the signature field.
//
//  1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        type covered           |  algorithm    |     labels    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         original TTL                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      signature expiration                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      signature inception                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            key  tag           |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
// |                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
// /                                                               /
// /                            signature                          /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// 4.1.1 Type Covered Field
//
//  The "type covered" is the type of the other RRs covered by this SIG.
//
// 4.1.2 Algorithm Number Field
//
//  This octet is as described in section 3.2.
//
// 4.1.3 Labels Field
//
//  The "labels" octet is an unsigned count of how many labels there are
//  in the original SIG RR owner name not counting the null label for
//  root and not counting any initial "*" for a wildcard.  If a secured
//  retrieval is the result of wild card substitution, it is necessary
//  for the resolver to use the original form of the name in verifying
//  the digital signature.  This field makes it easy to determine the
//  original form.
//
//  If, on retrieval, the RR appears to have a longer name than indicated
//  by "labels", the resolver can tell it is the result of wildcard
//  substitution.  If the RR owner name appears to be shorter than the
//  labels count, the SIG RR must be considered corrupt and ignored.  The
//  maximum number of labels allowed in the current DNS is 127 but the
//  entire octet is reserved and would be required should DNS names ever
//  be expanded to 255 labels.  The following table gives some examples.
//  The value of "labels" is at the top, the retrieved owner name on the
//  left, and the table entry is the name to use in signature
//  verification except that "bad" means the RR is corrupt.
//
//  labels= |  0  |   1  |    2   |      3   |      4   |
//  --------+-----+------+--------+----------+----------+
//         .|   . | bad  |  bad   |    bad   |    bad   |
//        d.|  *. |   d. |  bad   |    bad   |    bad   |
//      c.d.|  *. | *.d. |   c.d. |    bad   |    bad   |
//    b.c.d.|  *. | *.d. | *.c.d. |   b.c.d. |    bad   |
//  a.b.c.d.|  *. | *.d. | *.c.d. | *.b.c.d. | a.b.c.d. |
//
// 4.1.4 Original TTL Field
//
//  The "original TTL" field is included in the RDATA portion to avoid
//  (1) authentication problems that caching servers would otherwise
//  cause by decrementing the real TTL field and (2) security problems
//  that unscrupulous servers could otherwise cause by manipulating the
//  real TTL field.  This original TTL is protected by the signature
//  while the current TTL field is not.
//
//  NOTE:  The "original TTL" must be restored into the covered RRs when
//  the signature is verified (see Section 8).  This generaly implies
//  that all RRs for a particular type, name, and class, that is, all the
//  RRs in any particular RRset, must have the same TTL to start with.
//
// 4.1.5 Signature Expiration and Inception Fields
//
//  The SIG is valid from the "signature inception" time until the
//  "signature expiration" time.  Both are unsigned numbers of seconds
//  since the start of 1 January 1970, GMT, ignoring leap seconds.  (See
//  also Section 4.4.)  Ring arithmetic is used as for DNS SOA serial
//  numbers [RFC 1982] which means that these times can never be more
//  than about 68 years in the past or the future.  This means that these
//  times are ambiguous modulo ~136.09 years.  However there is no
//  security flaw because keys are required to be changed to new random
//  keys by [RFC 2541] at least every five years.  This means that the
//  probability that the same key is in use N*136.09 years later should
//  be the same as the probability that a random guess will work.
//
//  A SIG RR may have an expiration time numerically less than the
//  inception time if the expiration time is near the 32 bit wrap around
//  point and/or the signature is long lived.
//
//  (To prevent misordering of network requests to update a zone
//  dynamically, monotonically increasing "signature inception" times may
//  be necessary.)
//
//  A secure zone must be considered changed for SOA serial number
//  purposes not only when its data is updated but also when new SIG RRs
//  are inserted (ie, the zone or any part of it is re-signed).
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
// 4.1.7 Signer's Name Field
//
//  The "signer's name" field is the domain name of the signer generating
//  the SIG RR.  This is the owner name of the public KEY RR that can be
//  used to verify the signature.  It is frequently the zone which
//  contained the RRset being authenticated.  Which signers should be
//  authorized to sign what is a significant resolver policy question as
//  discussed in Section 6. The signer's name may be compressed with
//  standard DNS name compression when being transmitted over the
//  network.
//
// 4.1.8 Signature Field
//
//  The actual signature portion of the SIG RR binds the other RDATA
//  fields to the RRset of the "type covered" RRs with that owner name
//  and class.  This covered RRset is thereby authenticated.  To
//  accomplish this, a data sequence is constructed as follows:
//
//  data = RDATA | RR(s)...
//
//  where "|" is concatenation,
//
//  RDATA is the wire format of all the RDATA fields in the SIG RR itself
//  (including the canonical form of the signer's name) before but not
//  including the signature, and
//
//  RR(s) is the RRset of the RR(s) of the type covered with the same
//  owner name and class as the SIG RR in canonical form and order as
//  defined in Section 8.
//
//  How this data sequence is processed into the signature is algorithm
//  dependent.  These algorithm dependent formats and procedures are
//  described in separate documents (Section 3.2).
//
//  SIGs SHOULD NOT be included in a zone for any "meta-type" such as
//  ANY, AXFR, etc. (but see section 5.6.2 with regard to IXFR).
//
// SIG { type_covered: u16, algorithm: SecAlgorithm, num_labels: u8, original_ttl: u32,
//       sig_expiration: u32, sig_inception: u32, key_tag: u16, signer_name: Name, sig: Vec<u8> }
pub fn read(decoder: &mut BinDecoder) -> DecodeResult<RData> {
  // TODO should we verify here? or elsewhere...
  let type_covered = try!(decoder.read_u16());
  let algorithm = try!(Algorithm::read(decoder));
  let num_labels = try!(decoder.read_u8());
  let original_ttl = try!(decoder.read_u32());
  let sig_expiration = try!(decoder.read_u32());
  let sig_inception = try!(decoder.read_u32());
  let key_tag = try!(decoder.read_u16());
  let signer_name = try!(Name::read(decoder));
  let sig = try!(decoder.read_vec(algorithm.get_hash_type().md_len()));

  Ok(RData::SIG {
    type_covered:   type_covered,
    algorithm:      algorithm,
    num_labels:     num_labels,
    original_ttl:   original_ttl,
    sig_expiration: sig_expiration,
    sig_inception:  sig_expiration,
    key_tag:        key_tag,
    signer_name:    signer_name,
    sig:            sig,
  })
}

pub fn emit(encoder: &mut BinEncoder, sig: &RData) -> EncodeResult {
  if let RData::SIG { type_covered, algorithm, num_labels, original_ttl, sig_expiration, sig_inception, key_tag, ref signer_name, ref sig } = *sig {
    try!(encoder.emit_u16(type_covered));
    try!(algorithm.emit(encoder));
    try!(encoder.emit(num_labels));
    try!(encoder.emit_u32(original_ttl));
    try!(encoder.emit_u32(sig_expiration));
    try!(encoder.emit_u32(sig_inception));
    try!(encoder.emit_u16(key_tag));
    try!(signer_name.emit(encoder));
    try!(encoder.emit_vec(sig));
    Ok(())
  } else {
    panic!("wrong type here {:?}", sig);
  }
}

// VENERA      Action\.domains (
//                                 20     ; SERIAL
//                                 7200   ; REFRESH
//                                 600    ; RETRY
//                                 3600000; EXPIRE
//                                 60)    ; MINIMUM
// pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<RData> {
//   let mut token = tokens.iter();
//
//   let mname: Name = try!(token.next().ok_or(ParseError::MissingToken("mname".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//   let rname: Name = try!(token.next().ok_or(ParseError::MissingToken("rname".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Name::parse(s, origin)} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//   let mut list = try!(token.next().ok_or(ParseError::MissingToken("List".to_string())).and_then(|t| if let &Token::List(ref v) = t {Ok(v)} else {Err(ParseError::UnexpectedToken(t.clone()))} )).iter();
//
//   let serial: u32 = try!(list.next().ok_or(ParseError::MissingToken("serial".to_string())).and_then(|s| Ok(try!(s.parse()))));
//   let refresh: i32 = try!(list.next().ok_or(ParseError::MissingToken("refresh".to_string())).and_then(|s| Ok(try!(s.parse()))));
//   let retry: i32 = try!(list.next().ok_or(ParseError::MissingToken("retry".to_string())).and_then(|s| Ok(try!(s.parse()))));
//   let expire: i32 = try!(list.next().ok_or(ParseError::MissingToken("expire".to_string())).and_then(|s| Ok(try!(s.parse()))));
//   let minimum: u32 = try!(list.next().ok_or(ParseError::MissingToken("minimum".to_string())).and_then(|s| Ok(try!(s.parse()))));
//
//
//   // let serial: u32 = try!(token.next().ok_or(ParseError::MissingToken("serial".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//   // let refresh: i32 = try!(token.next().ok_or(ParseError::MissingToken("refresh".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//   // let retry: i32 = try!(token.next().ok_or(ParseError::MissingToken("retry".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//   // let expire: i32 = try!(token.next().ok_or(ParseError::MissingToken("expire".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//   // let minimum: u32 = try!(token.next().ok_or(ParseError::MissingToken("minimum".to_string())).and_then(|t| if let &Token::CharData(ref s) = t {Ok(try!(s.parse()))} else {Err(ParseError::UnexpectedToken(t.clone()))} ));
//
//   Ok(RData::SOA{
//     mname:   mname,
//     rname:   rname,
//     serial:  serial,
//     refresh: refresh,
//     retry:   retry,
//     expire:  expire,
//     minimum: minimum,
//   })
// }
