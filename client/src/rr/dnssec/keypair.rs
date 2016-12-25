// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "openssl")]
use openssl::crypto::rsa::RSA as OpenSslRsa;
#[cfg(feature = "openssl")]
use openssl::bn::BigNum;

use ::error::*;
use ::rr::{Name, RData, Record, RecordType};
use ::rr::dnssec::{Algorithm, DigestType};
use ::rr::rdata::DNSKEY;

/// A public and private key pair.
#[derive(Debug)]
pub enum KeyPair {
  #[cfg(feature = "openssl")]
  RSA { rsa: OpenSslRsa },
}

impl KeyPair {
  pub fn from_rsa(rsa: OpenSslRsa) -> Self {
    KeyPair::RSA{rsa: rsa}
  }

  pub fn from_vec(public_key: &[u8], algorithm: Algorithm) -> DecodeResult<Self> {
    match algorithm {
      #[cfg(feature = "openssl")]
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
        if public_key.len() < 3 || public_key.len() > (4096 + 3) { return Err(DecodeErrorKind::Message("bad public key").into()) }
        let mut num_exp_len_octs = 1;
        let mut len: u16 = public_key[0] as u16;
        if len == 0 {
          num_exp_len_octs = 3;
          len = ((public_key[1] as u16) << 8) | (public_key[2] as u16)
        }
        let len = len; // demut

        let e = try!(BigNum::new_from_slice(&public_key[(num_exp_len_octs as usize)..(len as usize + num_exp_len_octs)]));
        let n = try!(BigNum::new_from_slice(&public_key[(len as usize +num_exp_len_octs)..]));

        OpenSslRsa::from_public_components(n, e)
                   .map_err(|e| e.into())
                   .map(|rsa| Self::from_rsa(rsa))
      },
      // _ => Err(DecodeErrorKind::Message("openssl feature not enabled").into()),
    }
  }

  pub fn to_vec(&self) -> Vec<u8> {
    match *self {
      #[cfg(feature = "openssl")]
      KeyPair::RSA{ref rsa} => {
        let mut bytes: Vec<u8> = Vec::new();

        // this is to get us access to the exponent and the modulus
        let e: Vec<u8> = rsa.e().expect("RSA should have been initialized").to_vec();
        let n: Vec<u8> = rsa.n().expect("RSA should have been initialized").to_vec();

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
      },
      // _ => vec![],
    }
  }

  /// Creates a Record that represents the public key for this Signer
  ///
  /// # Arguments
  ///
  /// * `name` - name of the entity associated with this DNSKEY
  /// * `ttl` - the time to live for this DNSKEY
  ///
  /// # Return
  ///
  /// the DNSKEY record
  pub fn to_dnskey(&self, name: Name, ttl: u32, algorithm: Algorithm) -> Record {
    let mut record = Record::with(name.clone(), RecordType::DNSKEY, ttl);

    #[cfg(feature = "openssl")]
    {
      let rsa_bytes = self.to_vec();
      record.rdata(RData::DNSKEY(DNSKEY::new(true, true, false, algorithm, rsa_bytes)));
    }

    record
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
  pub fn sign(&self, algorithm: Algorithm, hash: &[u8]) -> DnsSecResult<Vec<u8>> {
    match *self {
      #[cfg(feature = "openssl")]
      KeyPair::RSA{ref rsa} => {
        rsa.sign(DigestType::from(algorithm).to_hash(), &hash).map_err(|e| e.into())
      }
    }
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
  pub fn verify(&self, algorithm: Algorithm, hash: &[u8], signature: &[u8]) -> DnsSecResult<()> {
    match *self {
      #[cfg(feature = "openssl")]
      KeyPair::RSA{ref rsa} => {
        rsa.verify(DigestType::from(algorithm).to_hash(), hash, signature).map_err(|e| e.into())
      }
    }
  }
}
