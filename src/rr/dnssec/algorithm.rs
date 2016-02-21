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
use openssl::crypto::pkey::{PKey, Role};
use openssl::crypto::rsa::RSA;
use openssl::crypto::hash;
use openssl::bn::BigNum;

use ::serialize::binary::*;
use ::error::*;

// RFC 6944             DNSSEC DNSKEY Algorithm Status           April 2013
//
// 2.2.  Algorithm Implementation Status Assignment Rationale
//
// RSASHA1 has an implementation status of Must Implement, consistent
// with [RFC4034].  RSAMD5 has an implementation status of Must Not
// Implement because of known weaknesses in MD5.
//
// The status of RSASHA1-NSEC3-SHA1 is set to Recommended to Implement
// as many deployments use NSEC3.  The status of RSA/SHA-256 and RSA/
// SHA-512 are also set to Recommended to Implement as major deployments
// (such as the root zone) use these algorithms [ROOTDPS].  It is
// believed that RSA/SHA-256 or RSA/SHA-512 algorithms will replace
// older algorithms (e.g., RSA/SHA-1) that have a perceived weakness.
//
// Likewise, ECDSA with the two identified curves (ECDSAP256SHA256 and
// ECDSAP384SHA384) is an algorithm that may see widespread use due to
// the perceived similar level of security offered with smaller key size
// compared to the key sizes of algorithms such as RSA.  Therefore,
// ECDSAP256SHA256 and ECDSAP384SHA384 are Recommended to Implement.
//
// All other algorithms used in DNSSEC specified without an
// implementation status are currently set to Optional.
//
// 2.3.  DNSSEC Implementation Status Table
//
// The DNSSEC algorithm implementation status table is listed below.
// Only the algorithms already specified for use with DNSSEC at the time
// of writing are listed.
//
//  +------------+------------+-------------------+-------------------+
//  |    Must    |  Must Not  |    Recommended    |      Optional     |
//  |  Implement | Implement  |   to Implement    |                   |
//  +------------+------------+-------------------+-------------------+
//  |            |            |                   |                   |
//  |   RSASHA1  |   RSAMD5   |   RSASHA256       |   Any             |
//  |            |            |   RSASHA1-NSEC3   |   registered      |
//  |            |            |    -SHA1          |   algorithm       |
//  |            |            |   RSASHA512       |   not listed in   |
//  |            |            |   ECDSAP256SHA256 |   this table      |
//  |            |            |   ECDSAP384SHA384 |                   |
//  +------------+------------+-------------------+-------------------+
//
//    This table does not list the Reserved values in the IANA registry
//    table or the values for INDIRECT (252), PRIVATE (253), and PRIVATEOID
//    (254).  These values may relate to more than one algorithm and are
//    therefore up to the implementer's discretion.  As noted, any
//    algorithm not listed in the table is Optional.  As of this writing,
//    the Optional algorithms are DSASHA1, DH, DSA-NSEC3-SHA1, and GOST-
//    ECC, but in general, anything not explicitly listed is Optional.
//
// 2.4.  Specifying New Algorithms and Updating the Status of Existing
//       Entries
//
//    [RFC6014] establishes a parallel procedure for adding a registry
//    entry for a new algorithm other than a standards track document.
//    Because any algorithm not listed in the foregoing table is Optional,
//    algorithms entered into the registry using the [RFC6014] procedure
//    are automatically Optional.
//
//    It has turned out to be useful for implementations to refer to a
//    single document that specifies the implementation status of every
//    algorithm.  Accordingly, when a new algorithm is to be registered
//    with a status other than Optional, this document shall be made
//    obsolete by a new document that adds the new algorithm to the table
//    in Section 2.3.  Similarly, if the status of any algorithm in the
//    table in Section 2.3 changes, a new document shall make this document
//    obsolete; that document shall include a replacement of the table in
//    Section 2.3.  This way, the goal of having one authoritative document
//    to specify all the status values is achieved.
//
//    This document cannot be updated, only made obsolete and replaced by a
//    successor document.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Algorithm {
  /// DO NOT USE, SHA1 is a compromised hashing function, it is here for backward compatability
  RSASHA1,
  RSASHA256,
  /// DO NOT USE, SHA1 is a compromised hashing function, it is here for backward compatability
  RSASHA1NSEC3SHA1,
  RSASHA512,
//  ECDSAP256SHA256, // not yet supported
//  ECDSAP384SHA384,
}

impl Algorithm {
  pub fn get_hash_type(self) -> hash::Type {
    match self {
      Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => hash::Type::SHA1,
      Algorithm::RSASHA256 => hash::Type::SHA256,
      Algorithm::RSASHA512 => hash::Type::SHA512,
//      Algorithm::ECDSAP256SHA256 => hash::Type::SHA256,
//      Algorithm::ECDSAP384SHA384 => hash::Type::SHA384,
    }
  }

  fn hash(&self, data: &[u8]) -> Vec<u8> {
    hash::hash(self.get_hash_type(), data)
  }

  pub fn sign(&self, private_key: &PKey, data: &[u8]) -> Vec<u8> {
    if !private_key.can(Role::Sign) { panic!("This key cannot be used for signing") }

    // calculate the hash...
    let hash = self.hash(data);

    // then sign and return
    private_key.sign(&hash)
  }

  pub fn verify(&self, public_key: &PKey, data: &[u8], signature: &[u8]) -> bool {
    if !public_key.can(Role::Verify) { panic!("This key cannot be used to verify signature") }

    // calculate the hash on the local data
    let hash = self.hash(data);

    // verify the remotely sent signature
    public_key.verify(&hash, signature)
  }

  /// http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
  pub fn from_u8(value: u8) -> DecodeResult<Self> {
    match value {
      5  => Ok(Algorithm::RSASHA1),
      7  => Ok(Algorithm::RSASHA1NSEC3SHA1),
      8  => Ok(Algorithm::RSASHA256),
      10 => Ok(Algorithm::RSASHA512),
//      13 => Algorithm::ECDSAP256SHA256,
//      14 => Algorithm::ECDSAP384SHA384,
      _ => Err(DecodeError::UnknownAlgorithmTypeValue(value)),
    }
  }

  /// length in bytes that the hash portion of this function will produce
  pub fn hash_len(&self) -> usize {
    match *self {
      Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => 20, // 160 bits
      Algorithm::RSASHA256 => 32, // 256 bits
      Algorithm::RSASHA512 => 64, // 512 bites
    }
  }

  pub fn public_key_from_vec(&self, public_key: &[u8]) -> DecodeResult<PKey> {
    match *self {
      Algorithm::RSASHA1 |
      Algorithm::RSASHA1NSEC3SHA1 |
      Algorithm::RSASHA256 |
      Algorithm::RSASHA512 => {
        // RFC 3110              RSA SIGs and KEYs in the DNS              May 2001
        //
        //       2. RSA Public KEY Resource Records
        //
        //  RSA public keys are stored in the DNS as KEY RRs using algorithm
        //  number 5 [RFC2535].  The structure of the algorithm specific portion
        //  of the RDATA part of such RRs is as shown below.
        //
        //        Field             Size
        //        -----             ----
        //        exponent length   1 or 3 octets (see text)
        //        exponent          as specified by length field
        //        modulus           remaining space
        //
        //  For interoperability, the exponent and modulus are each limited to
        //  4096 bits in length.  The public key exponent is a variable length
        //  unsigned integer.  Its length in octets is represented as one octet
        //  if it is in the range of 1 to 255 and by a zero octet followed by a
        //  two octet unsigned length if it is longer than 255 bytes.  The public
        //  key modulus field is a multiprecision unsigned integer.  The length
        //  of the modulus can be determined from the RDLENGTH and the preceding
        //  RDATA fields including the exponent.  Leading zero octets are
        //  prohibited in the exponent and modulus.
        //
        //  Note: KEY RRs for use with RSA/SHA1 DNS signatures MUST use this
        //  algorithm number (rather than the algorithm number specified in the
        //  obsoleted RFC 2537).
        //
        //  Note: This changes the algorithm number for RSA KEY RRs to be the
        //  same as the new algorithm number for RSA/SHA1 SIGs.
        if public_key.len() < 3 || public_key.len() > (4096 + 3) { return Err(DecodeError::BadPublicKey) }
        let mut num_exp_len_octs = 1;
        let mut len: u16 = public_key[0] as u16;
        if len == 0 {
          num_exp_len_octs = 3;
          len = ((public_key[1] as u16) << 8) | (public_key[2] as u16)
        }
        let len = len; // demut

        let mut pkey = PKey::new();
        let e = try!(BigNum::new_from_slice(&public_key[(num_exp_len_octs as usize)..(len as usize + num_exp_len_octs)]));
        let n = try!(BigNum::new_from_slice(&public_key[(len as usize +num_exp_len_octs)..]));

        let mut rsa = try!(RSA::new());
        rsa.set_e(e);
        rsa.set_n(n);
        pkey.set_rsa(rsa);
        Ok(pkey)
      }
    }
  }

  pub fn public_key_to_vec(&self, public_key: &PKey) -> Vec<u8> {
    match *self {
      Algorithm::RSASHA1 |
      Algorithm::RSASHA1NSEC3SHA1 |
      Algorithm::RSASHA256 |
      Algorithm::RSASHA512 => {
        let mut bytes: Vec<u8> = Vec::new();

        // this is to get us access to the exponent and the modulus
        let rsa: RSA = public_key.get_rsa();
        let e: Vec<u8> = rsa.e().expect("PKey should have been initialized").to_vec();
        let n: Vec<u8> = rsa.n().expect("PKey should have been initialized").to_vec();

        if e.len() > 255 {
          bytes.push(0);
          bytes.push((e.len() >> 8) as u8);
          bytes.push(e.len() as u8);
        } else {
          bytes.push(e.len() as u8);
        }

        bytes.extend_from_slice(&e);
        bytes.extend_from_slice(&n);

        bytes
      }
    }
  }
}

impl BinSerializable<Algorithm> for Algorithm {
  // http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
  fn read(decoder: &mut BinDecoder) -> DecodeResult<Algorithm> {
    let algorithm_id = try!(decoder.read_u8());
    Algorithm::from_u8(algorithm_id)
  }

  fn emit(&self, encoder: &mut BinEncoder) -> EncodeResult {
    encoder.emit(u8::from(*self))
  }
}

impl From<&'static str> for Algorithm {
  fn from(s: &'static str) -> Algorithm {
    match s {
      "RSASHA1" => Algorithm::RSASHA1,
      "RSASHA256" => Algorithm::RSASHA256,
      "RSASHA1-NSEC3-SHA1" => Algorithm::RSASHA1NSEC3SHA1,
      "RSASHA512" => Algorithm::RSASHA512,
//      "ECDSAP256SHA256" => Algorithm::ECDSAP256SHA256,
//      "ECDSAP384SHA384" => Algorithm::ECDSAP384SHA384,
      _ => panic!("unrecognized string {}", s),
    }
  }
}

impl From<Algorithm> for &'static str {
  fn from(a: Algorithm) -> &'static str {
    match a {
      Algorithm::RSASHA1 => "RSASHA1",
      Algorithm::RSASHA256 => "RSASHA256",
      Algorithm::RSASHA1NSEC3SHA1 => "RSASHA1-NSEC3-SHA1",
      Algorithm::RSASHA512 => "RSASHA512",
//      ECDSAP256SHA256 => "ECDSAP256SHA256",
//      ECDSAP384SHA384 => "ECDSAP384SHA384",
    }
  }
}

impl From<Algorithm> for u8 {
  fn from(a: Algorithm) -> u8 {
    match a {
      Algorithm::RSASHA1 => 5,
      Algorithm::RSASHA1NSEC3SHA1 => 7,
      Algorithm::RSASHA256 => 8,
      Algorithm::RSASHA512 => 10,
//      ECDSAP256SHA256 => 13,
//      ECDSAP384SHA384 => 14,
    }
  }
}

#[cfg(test)]
mod test {
  use super::Algorithm;
  use openssl::crypto::pkey;
  use openssl::crypto::pkey::EncryptionPadding;
  use openssl::crypto::pkey::{PKey, Parts, Role};

  #[test]
  fn test_hashing() {
    let bytes = b"www.example.com";
    let mut pkey = pkey::PKey::new();
    pkey.gen(2048);

    for algorithm in &[Algorithm::RSASHA1,
                       Algorithm::RSASHA256,
                       Algorithm::RSASHA1NSEC3SHA1,
                       Algorithm::RSASHA512] {
      let sig = algorithm.sign(&pkey, bytes);
      assert!(algorithm.verify(&pkey, bytes, &sig));
    }
  }

  #[test]
  fn test_binary_public_key() {
    let bytes = b"www.example.com".to_vec();
    let mut pkey = pkey::PKey::new();
    pkey.gen(2048);

    let crypt = pkey.encrypt(&bytes);
    let decrypt = pkey.decrypt(&crypt);

    assert_eq!(bytes, decrypt);
    println!("pkey: {:?}", pkey.save_pub());

    let algorithm = Algorithm::RSASHA256;

    let bin_key = algorithm.public_key_to_vec(&pkey);
    let new_key = algorithm.public_key_from_vec(&bin_key).expect("couldn't read bin_key");

    assert!(new_key.can(Role::Encrypt));
    assert!(new_key.can(Role::Verify));
    assert!(!new_key.can(Role::Decrypt));
    assert!(!new_key.can(Role::Sign));


    let crypt = new_key.encrypt(&bytes);
    let decrypt = pkey.decrypt(&crypt);

    assert_eq!(bytes, decrypt);
  }
}
