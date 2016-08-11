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

//! signer is a structure for performing many of the signing processes of the DNSSec specification

use chrono::Duration;
use openssl::crypto::pkey::{PKey, Role};

use ::op::Message;
use ::rr::dnssec::{Algorithm, DigestType};
use ::rr::{DNSClass, Name, Record, RecordType, RData};
use ::serialize::binary::{BinEncoder, BinSerializable, EncodeMode};
use ::rr::rdata::{sig, DNSKEY};


/// Use for performing signing and validation of DNSSec based components.
pub struct Signer {
  algorithm: Algorithm,
  pkey: PKey,
  signer_name: Name,
  sig_duration: Duration,
}

impl Signer {
  /// Version of Signer for verifying RRSIGs and SIG0 records.
  pub fn new_verifier(algorithm: Algorithm, pkey: PKey, signer_name: Name) -> Self {
    Signer{ algorithm: algorithm, pkey: pkey, signer_name: signer_name, sig_duration: Duration::zero() }
  }

  /// Version of Signer for signing RRSIGs and SIG0 records.
  pub fn new(algorithm: Algorithm, pkey: PKey, signer_name: Name, sig_duration: Duration) -> Self {
    Signer{ algorithm: algorithm, pkey: pkey, signer_name: signer_name, sig_duration: sig_duration }
  }

  pub fn get_algorithm(&self) -> Algorithm { self.algorithm }
  pub fn get_sig_duration(&self) -> Duration { self.sig_duration }
  pub fn get_signer_name(&self) -> &Name { &self.signer_name }
  pub fn get_pkey(&self) -> &PKey { &self.pkey }

  pub fn get_public_key(&self) -> Vec<u8> {
    self.algorithm.public_key_to_vec(&self.pkey)
  }

  /// Creates a Record that represents the public key for this Signer
  pub fn to_dnskey(&self, name: Name, ttl: u32) -> Record {
    let mut record = Record::with(name.clone(), RecordType::DNSKEY, ttl);
    record.rdata(RData::DNSKEY(
      DNSKEY::new(true, true, false,
        self.algorithm,
        self.get_public_key())
    ));

    record
  }

  /// The key tag is calculated as a hash to more quickly lookup a DNSKEY.
  ///
  /// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
  ///
  /// ```text
  /// RFC 2535                DNS Security Extensions               March 1999
  ///
  /// 4.1.6 Key Tag Field
  ///
  ///  The "key Tag" is a two octet quantity that is used to efficiently
  ///  select between multiple keys which may be applicable and thus check
  ///  that a public key about to be used for the computationally expensive
  ///  effort to check the signature is possibly valid.  For algorithm 1
  ///  (MD5/RSA) as defined in [RFC 2537], it is the next to the bottom two
  ///  octets of the public key modulus needed to decode the signature
  ///  field.  That is to say, the most significant 16 of the least
  ///  significant 24 bits of the modulus in network (big endian) order. For
  ///  all other algorithms, including private algorithms, it is calculated
  ///  as a simple checksum of the KEY RR as described in Appendix C.
  ///
  /// Appendix C: Key Tag Calculation
  ///
  ///  The key tag field in the SIG RR is just a means of more efficiently
  ///  selecting the correct KEY RR to use when there is more than one KEY
  ///  RR candidate available, for example, in verifying a signature.  It is
  ///  possible for more than one candidate key to have the same tag, in
  ///  which case each must be tried until one works or all fail.  The
  ///  following reference implementation of how to calculate the Key Tag,
  ///  for all algorithms other than algorithm 1, is in ANSI C.  It is coded
  ///  for clarity, not efficiency.  (See section 4.1.6 for how to determine
  ///  the Key Tag of an algorithm 1 key.)
  ///
  ///  /* assumes int is at least 16 bits
  ///     first byte of the key tag is the most significant byte of return
  ///     value
  ///     second byte of the key tag is the least significant byte of
  ///     return value
  ///     */
  ///
  ///  int keytag (
  ///
  ///          unsigned char key[],  /* the RDATA part of the KEY RR */
  ///          unsigned int keysize, /* the RDLENGTH */
  ///          )
  ///  {
  ///  long int    ac;    /* assumed to be 32 bits or larger */
  ///
  ///  for ( ac = 0, i = 0; i < keysize; ++i )
  ///      ac += (i&1) ? key[i] : key[i]<<8;
  ///  ac += (ac>>16) & 0xFFFF;
  ///  return ac & 0xFFFF;
  ///  }
  /// ```
  pub fn calculate_key_tag(&self) -> u16 {
    let mut ac: usize = 0;

    for (i,k) in self.get_public_key().iter().enumerate() {
      ac += if i & 0x0001 == 0x0001 { *k as usize } else { (*k as usize) << 8 };
    }

    ac += (ac >> 16 ) & 0xFFFF;
    return (ac & 0xFFFF) as u16; // this is unnecessary, no?
  }

  fn hash_message(&self, message: &Message) -> Vec<u8> {
    // TODO: should perform the serialization and sign block by block to reduce the max memory
    //  usage, though at 4k max, this is probably unnecessary... For AXFR and large zones, it's
    //  more important
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    {
      let mut encoder: BinEncoder = BinEncoder::with_mode(&mut buf, EncodeMode::Signing);
      message.emit(&mut encoder).unwrap(); // coding error if this panics (i think?)
    }

    DigestType::from(self.algorithm).hash(&buf)
  }

  /// Signs the given message, returning the signature bytes.
  ///
  /// # Arguments
  ///
  /// * `message` - the message to sign
  ///
  /// ```text
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
  ///  data = full response (less transaction SIG) | full query
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
  /// ```
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
    self.sign(&hash)
  }

  /// Verifies a message with the against the given signature
  ///
  /// # Arguments
  ///
  /// `message` - the message to verify
  /// `signature` - the signature to use for validation
  ///
  /// # Return value
  ///
  /// `true` if the message could be validated against the signature, `false` otherwise
  pub fn verify_message(&self, message: &Message, signature: &[u8]) -> bool {
    assert!(self.pkey.can(Role::Verify)); // this is bad code, not expected in regular runtime
    let hash = self.hash_message(message);
    self.verify(&hash, signature)
  }

  // RFC 4035             DNSSEC Protocol Modifications            March 2005
  //
  // 5.3.  Authenticating an RRset with an RRSIG RR
  //
  //    A validator can use an RRSIG RR and its corresponding DNSKEY RR to
  //    attempt to authenticate RRsets.  The validator first checks the RRSIG
  //    RR to verify that it covers the RRset, has a valid time interval, and
  //    identifies a valid DNSKEY RR.  The validator then constructs the
  //    canonical form of the signed data by appending the RRSIG RDATA
  //    (excluding the Signature Field) with the canonical form of the
  //    covered RRset.  Finally, the validator uses the public key and
  //    signature to authenticate the signed data.  Sections 5.3.1, 5.3.2,
  //    and 5.3.3 describe each step in detail.
  //
  // 5.3.1.  Checking the RRSIG RR Validity
  //
  //    A security-aware resolver can use an RRSIG RR to authenticate an
  //    RRset if all of the following conditions hold:
  //
  //    o  The RRSIG RR and the RRset MUST have the same owner name and the
  //       same class.
  //
  //    o  The RRSIG RR's Signer's Name field MUST be the name of the zone
  //       that contains the RRset.
  //
  //    o  The RRSIG RR's Type Covered field MUST equal the RRset's type.
  //
  //    o  The number of labels in the RRset owner name MUST be greater than
  //       or equal to the value in the RRSIG RR's Labels field.
  //
  //    o  The validator's notion of the current time MUST be less than or
  //       equal to the time listed in the RRSIG RR's Expiration field.
  //
  //    o  The validator's notion of the current time MUST be greater than or
  //       equal to the time listed in the RRSIG RR's Inception field.
  //
  //    o  The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
  //       match the owner name, algorithm, and key tag for some DNSKEY RR in
  //       the zone's apex DNSKEY RRset.
  //
  //    o  The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
  //       RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
  //       set.
  //
  //    It is possible for more than one DNSKEY RR to match the conditions
  //    above.  In this case, the validator cannot predetermine which DNSKEY
  //    RR to use to authenticate the signature, and it MUST try each
  //    matching DNSKEY RR until either the signature is validated or the
  //    validator has run out of matching public keys to try.
  //
  //    Note that this authentication process is only meaningful if the
  //    validator authenticates the DNSKEY RR before using it to validate
  //    signatures.  The matching DNSKEY RR is considered to be authentic if:
  //
  //    o  the apex DNSKEY RRset containing the DNSKEY RR is considered
  //       authentic; or
  //
  //    o  the RRset covered by the RRSIG RR is the apex DNSKEY RRset itself,
  //       and the DNSKEY RR either matches an authenticated DS RR from the
  //       parent zone or matches a trust anchor.
  //
  // 5.3.2.  Reconstructing the Signed Data
  //
  //    Once the RRSIG RR has met the validity requirements described in
  //    Section 5.3.1, the validator has to reconstruct the original signed
  //    data.  The original signed data includes RRSIG RDATA (excluding the
  //    Signature field) and the canonical form of the RRset.  Aside from
  //    being ordered, the canonical form of the RRset might also differ from
  //    the received RRset due to DNS name compression, decremented TTLs, or
  //    wildcard expansion.  The validator should use the following to
  //    reconstruct the original signed data:
  //
  //          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
  //
  //             "|" denotes concatenation
  //
  //             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
  //                with the Signature field excluded and the Signer's Name
  //                in canonical form.
  //
  //             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
  //
  //                name is calculated according to the function below
  //
  //                class is the RRset's class
  //
  //                type is the RRset type and all RRs in the class
  //
  //                OrigTTL is the value from the RRSIG Original TTL field
  //
  //                All names in the RDATA field are in canonical form
  //
  //                The set of all RR(i) is sorted into canonical order.
  //
  //             To calculate the name:
  //                let rrsig_labels = the value of the RRSIG Labels field
  //
  //                let fqdn = RRset's fully qualified domain name in
  //                                canonical form
  //
  //                let fqdn_labels = Label count of the fqdn above.
  //
  //                if rrsig_labels = fqdn_labels,
  //                    name = fqdn
  //
  //                if rrsig_labels < fqdn_labels,
  //                   name = "*." | the rightmost rrsig_label labels of the
  //                                 fqdn
  //
  //                if rrsig_labels > fqdn_labels
  //                   the RRSIG RR did not pass the necessary validation
  //                   checks and MUST NOT be used to authenticate this
  //                   RRset.
  //
  //    The canonical forms for names and RRsets are defined in [RFC4034].
  //
  //    NSEC RRsets at a delegation boundary require special processing.
  //    There are two distinct NSEC RRsets associated with a signed delegated
  //    name.  One NSEC RRset resides in the parent zone, and specifies which
  //    RRsets are present at the parent zone.  The second NSEC RRset resides
  //    at the child zone and identifies which RRsets are present at the apex
  //    in the child zone.  The parent NSEC RRset and child NSEC RRset can
  //    always be distinguished as only a child NSEC RR will indicate that an
  //    SOA RRset exists at the name.  When reconstructing the original NSEC
  //    RRset for the delegation from the parent zone, the NSEC RRs MUST NOT
  //    be combined with NSEC RRs from the child zone.  When reconstructing
  //    the original NSEC RRset for the apex of the child zone, the NSEC RRs
  //    MUST NOT be combined with NSEC RRs from the parent zone.
  //
  //    Note that each of the two NSEC RRsets at a delegation point has a
  //    corresponding RRSIG RR with an owner name matching the delegated
  //    name, and each of these RRSIG RRs is authoritative data associated
  //    with the same zone that contains the corresponding NSEC RRset.  If
  //    necessary, a resolver can tell these RRSIG RRs apart by checking the
  //    Signer's Name field.
  //
  // 5.3.3.  Checking the Signature
  //
  //    Once the resolver has validated the RRSIG RR as described in Section
  //    5.3.1 and reconstructed the original signed data as described in
  //    Section 5.3.2, the validator can attempt to use the cryptographic
  //    signature to authenticate the signed data, and thus (finally!)
  //    authenticate the RRset.
  //
  //    The Algorithm field in the RRSIG RR identifies the cryptographic
  //    algorithm used to generate the signature.  The signature itself is
  //    contained in the Signature field of the RRSIG RDATA, and the public
  //    key used to verify the signature is contained in the Public Key field
  //    of the matching DNSKEY RR(s) (found in Section 5.3.1).  [RFC4034]
  //    provides a list of algorithm types and provides pointers to the
  //    documents that define each algorithm's use.
  //
  //    Note that it is possible for more than one DNSKEY RR to match the
  //    conditions in Section 5.3.1.  In this case, the validator can only
  //    determine which DNSKEY RR is correct by trying each matching public
  //    key until the validator either succeeds in validating the signature
  //    or runs out of keys to try.
  //
  //    If the Labels field of the RRSIG RR is not equal to the number of
  //    labels in the RRset's fully qualified owner name, then the RRset is
  //    either invalid or the result of wildcard expansion.  The resolver
  //    MUST verify that wildcard expansion was applied properly before
  //    considering the RRset to be authentic.  Section 5.3.4 describes how
  //    to determine whether a wildcard was applied properly.
  //
  //    If other RRSIG RRs also cover this RRset, the local resolver security
  //    policy determines whether the resolver also has to test these RRSIG
  //    RRs and how to resolve conflicts if these RRSIG RRs lead to differing
  //    results.
  //
  //    If the resolver accepts the RRset as authentic, the validator MUST
  //    set the TTL of the RRSIG RR and each RR in the authenticated RRset to
  //    a value no greater than the minimum of:
  //
  //    o  the RRset's TTL as received in the response;
  //
  //    o  the RRSIG RR's TTL as received in the response;
  //
  //    o  the value in the RRSIG RR's Original TTL field; and
  //
  //    o  the difference of the RRSIG RR's Signature Expiration time and the
  //       current time.
  //
  // 5.3.4.  Authenticating a Wildcard Expanded RRset Positive Response
  //
  //    If the number of labels in an RRset's owner name is greater than the
  //    Labels field of the covering RRSIG RR, then the RRset and its
  //    covering RRSIG RR were created as a result of wildcard expansion.
  //    Once the validator has verified the signature, as described in
  //    Section 5.3, it must take additional steps to verify the non-
  //    existence of an exact match or closer wildcard match for the query.
  //    Section 5.4 discusses these steps.
  //
  //    Note that the response received by the resolver should include all
  //    NSEC RRs needed to authenticate the response (see Section 3.1.3).
  //
  /// name is the the name of the records in the rrset
  pub fn hash_rrset(&self, name: &Name, dns_class: DNSClass, num_labels: u8,
                    type_covered: RecordType, algorithm: Algorithm, original_ttl: u32,
                    sig_expiration: u32, sig_inception: u32, key_tag: u16, signer_name: &Name,
                    records: &[Record]) -> Vec<u8> {
    // TODO: change this to a BTreeSet so that it's preordered, no sort necessary
    let mut rrset: Vec<&Record> = Vec::new();

    // collect only the records for this rrset
    for record in records {
      if dns_class == record.get_dns_class() &&
      type_covered == record.get_rr_type() &&
      name == record.get_name() {
        rrset.push(record);
      }
    }

    // put records in canonical order
    rrset.sort();

    let name: Name = if let Some(name) = Self::determine_name(name, num_labels) {
      name
    } else {
      // TODO: this should be an error
      warn!("could not determine name from {}", name);
      return vec![]
    };

    let mut buf: Vec<u8> = Vec::new();

    {
      let mut encoder: BinEncoder = BinEncoder::new(&mut buf);
      encoder.set_canonical_names(true);

      //          signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
      //
      //             "|" denotes concatenation
      //
      //             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
      //                with the Signature field excluded and the Signer's Name
      //                in canonical form.
      assert!(sig::emit_pre_sig(&mut encoder, type_covered, algorithm,
                          name.num_labels(), original_ttl, sig_expiration,
                          sig_inception, key_tag, signer_name).is_ok());

      // construct the rrset signing data
      for record in rrset {
        //             RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
        //
        //                name is calculated according to the function in the RFC 4035
        assert!(name.emit_as_canonical(&mut encoder, true).is_ok());
        //
        //                type is the RRset type and all RRs in the class
        assert!(type_covered.emit(&mut encoder).is_ok());
        //
        //                class is the RRset's class
        assert!(dns_class.emit(&mut encoder).is_ok());
        //
        //                OrigTTL is the value from the RRSIG Original TTL field
        assert!(encoder.emit_u32(original_ttl).is_ok());
        //
        //                RDATA length
        // TODO: add support to the encoder to set a marker to go back and write the length
        let mut rdata_buf = Vec::new();
        {
          let mut rdata_encoder = BinEncoder::new(&mut rdata_buf);
          rdata_encoder.set_canonical_names(true);
          assert!(record.get_rdata().emit(&mut rdata_encoder).is_ok());
        }
        assert!(encoder.emit_u16(rdata_buf.len() as u16).is_ok());
        //
        //                All names in the RDATA field are in canonical form (set above)
        assert!(encoder.emit_vec(&rdata_buf).is_ok());
      }
    }

    DigestType::from(self.algorithm).hash(&buf)
  }

  pub fn hash_rrset_with_rrsig(&self, rrsig: &Record, records: &[Record]) -> Vec<u8> {
    if let &RData::SIG(ref sig) = rrsig.get_rdata() {
      self.hash_rrset(rrsig.get_name(), rrsig.get_dns_class(),
                      sig.get_num_labels(), sig.get_type_covered(), sig.get_algorithm(),
                      sig.get_original_ttl(), sig.get_sig_expiration(), sig.get_sig_inception(),
                      sig.get_key_tag(), sig.get_signer_name(), records)
    } else {
      error!("rdata is not of type SIG: {:?}", rrsig.get_rdata());
      vec![]
    }
  }

  fn determine_name(name: &Name, num_labels: u8) -> Option<Name> {
    //             To calculate the name:
    //                let rrsig_labels = the value of the RRSIG Labels field
    //
    //                let fqdn = RRset's fully qualified domain name in
    //                                canonical form
    //
    //                let fqdn_labels = Label count of the fqdn above.
    let fqdn_labels = name.num_labels();
    //                if rrsig_labels = fqdn_labels,
    //                    name = fqdn

    if fqdn_labels == num_labels {
      return Some(name.clone());
    }
    //                if rrsig_labels < fqdn_labels,
    //                   name = "*." | the rightmost rrsig_label labels of the
    //                                 fqdn
    if num_labels < fqdn_labels {
      let mut star_name: Name = Name::new().label("*");
      let rightmost = name.trim_to(num_labels as usize);
      if !rightmost.is_root() {
        star_name.append(&rightmost);
        return Some(star_name);
      }
      return Some(star_name);
    }
    //
    //                if rrsig_labels > fqdn_labels
    //                   the RRSIG RR did not pass the necessary validation
    //                   checks and MUST NOT be used to authenticate this
    //                   RRset.
    // TODO: this should be an error
    None
  }

  /// Signs a hash.
  ///
  /// This will panic if the `key` is not a private key and can be used for signing.
  ///
  /// # Arguments
  ///
  /// * `hash` - the hashed resource record set, see `hash_rrset`.
  ///
  /// # Return value
  ///
  /// The signature, ready to be stored in an `RData::RRSIG`.
  pub fn sign(&self, hash: &[u8]) -> Vec<u8> {
    assert!(self.pkey.can(Role::Sign)); // this is bad code, not expected in regular runtime
    self.pkey.sign_with_hash(&hash, DigestType::from(self.algorithm).to_hash())
  }

  /// Verifies the hash matches the signature with the current `key`.
  ///
  /// # Arguments
  ///
  /// * `hash` - the hash to be validated, see `hash_rrset`
  /// * `signature` - the signature to use to verify the hash, extracted from an `RData::RRSIG`
  ///                 for example.
  ///
  /// # Return value
  ///
  /// True if and only if the signature is valid for the hash. This will always return
  /// false if the `key`.
  pub fn verify(&self, hash: &[u8], signature: &[u8]) -> bool {
    if !self.pkey.can(Role::Verify) {
      // this doesn't panic b/c the public key might just have been bad, and so this would fail
      //  in a bad data situation, therefore false instead of panic
      debug!("pkey can not be used to verify");
      return false;
    }
    self.pkey.verify_with_hash(hash, signature, DigestType::from(self.algorithm).to_hash())
  }
}

#[test]
fn test_sign_and_verify_message_sig0() {
  use ::rr::Name;
  use ::op::{Message, Query, UpdateMessage};

  let origin: Name = Name::parse("example.com.", None).unwrap();
  let mut question: Message = Message::new();
  let mut query: Query = Query::new();
  query.name(origin.clone());
  question.add_query(query);

  let mut pkey = PKey::new();
  pkey.gen(512);
  let signer = Signer::new(Algorithm::RSASHA256, pkey, Name::root(), Duration::max_value());

  let sig = signer.sign_message(&question);
  println!("sig: {:?}", sig);

  assert!(!sig.is_empty());
  assert!(signer.verify_message(&question, &sig));

  // now test that the sig0 record works correctly.
  assert!(question.get_sig0().is_empty());
  question.sign(&signer, 0);
  assert!(!question.get_sig0().is_empty());

  let sig = signer.sign_message(&question);
  println!("sig after sign: {:?}", sig);

  if let &RData::SIG(ref sig) = question.get_sig0()[0].get_rdata() {
    assert!(signer.verify_message(&question, sig.get_sig()));
  }
}

#[test]
fn test_hash_rrset() {
  use ::rr::{Name, RecordType};
  use ::rr::rdata::SIG;

  let mut pkey = PKey::new();
  pkey.gen(512);
  let signer = Signer::new(Algorithm::RSASHA256, pkey, Name::root(), Duration::max_value());

  let origin: Name = Name::parse("example.com.", None).unwrap();
  let rrsig = Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::SIG(SIG::new(RecordType::NS, Algorithm::RSASHA256, origin.num_labels(), 86400,
        5, 0, signer.calculate_key_tag(), origin.clone(), vec![]))).clone();
  let rrset = vec![Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(),
                   Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone()];

  let hash = signer.hash_rrset_with_rrsig(&rrsig, &rrset);
  assert!(!hash.is_empty());

  let rrset = vec![Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::CNAME).dns_class(DNSClass::IN).rdata(RData::CNAME(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(), // different type
                   Record::new().name(Name::parse("www.example.com.", None).unwrap()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(), // different name
                   Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::CH).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(), // different class
                   Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(),
                   Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone()];

  let filtered_hash = signer.hash_rrset_with_rrsig(&rrsig, &rrset);
  assert!(!filtered_hash.is_empty());
  assert_eq!(hash, filtered_hash);
}

#[test]
fn test_sign_and_verify_rrset() {
  use ::rr::RecordType;
  use ::rr::Name;
  use ::rr::rdata::SIG;

  let mut pkey = PKey::new();
  pkey.gen(512);
  let signer = Signer::new(Algorithm::RSASHA256, pkey, Name::root(), Duration::max_value());

  let origin: Name = Name::parse("example.com.", None).unwrap();
  let rrsig = Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::SIG(SIG::new(RecordType::NS, Algorithm::RSASHA256, origin.num_labels(), 86400,
        5, 0, signer.calculate_key_tag(), origin.clone(), vec![]))).clone();
  let rrset = vec![Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()) ).clone(),
                   Record::new().name(origin.clone()).ttl(86400).rr_type(RecordType::NS).dns_class(DNSClass::IN).rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()) ).clone()];

  let hash = signer.hash_rrset_with_rrsig(&rrsig, &rrset);
  let sig = signer.sign(&hash);

  assert!(signer.verify(&hash, &sig));
}

#[test]
fn test_calculate_key_tag() {
  let mut pkey = PKey::new();
  pkey.gen(512);
  println!("pkey: {:?}", pkey.save_pub());
  let signer = Signer::new(Algorithm::RSASHA256, pkey, Name::root(), Duration::max_value());
  let key_tag = signer.calculate_key_tag();

  println!("key_tag: {}", key_tag);
  assert!(key_tag > 0);
}
