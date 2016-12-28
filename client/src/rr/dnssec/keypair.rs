// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "openssl")]
use openssl::rsa::Rsa as OpenSslRsa;
#[cfg(feature = "openssl")]
use openssl::sign::{Signer, Verifier};
#[cfg(feature = "openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "openssl")]
use openssl::bn::BigNum;

use ::error::*;
use ::rr::{Name, RData, Record, RecordType};
use ::rr::dnssec::{Algorithm, DigestType};
use ::rr::rdata::DNSKEY;

/// A public and private key pair.
pub enum KeyPair {
  #[cfg(feature = "openssl")]
  RSA { pkey: PKey },
  #[cfg(feature = "openssl")]
  ECDSA {},
}

impl KeyPair {
  pub fn from_rsa(rsa: OpenSslRsa) -> DnsSecResult<Self> {
    PKey::from_rsa(rsa).map(|pkey| KeyPair::RSA{pkey: pkey}).map_err(|e| e.into())
  }

  pub fn from_vec(public_key: &[u8], algorithm: Algorithm) -> DnsSecResult<Self> {
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
        if public_key.len() < 3 || public_key.len() > (4096 + 3) { return Err(DnsSecErrorKind::Message("bad public key").into()) }
        let mut num_exp_len_octs = 1;
        let mut len: u16 = public_key[0] as u16;
        if len == 0 {
          num_exp_len_octs = 3;
          len = ((public_key[1] as u16) << 8) | (public_key[2] as u16)
        }
        let len = len; // demut

        let e = try!(BigNum::from_slice(&public_key[(num_exp_len_octs as usize)..(len as usize + num_exp_len_octs)]));
        let n = try!(BigNum::from_slice(&public_key[(len as usize +num_exp_len_octs)..]));

        OpenSslRsa::from_public_components(n, e)
                   .map_err(|e| e.into())
                   .and_then(|rsa| Self::from_rsa(rsa))
      },
      #[cfg(feature = "openssl")]
      Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
        Ok(KeyPair::ECDSA{})
      }
      // _ => Err(DecodeErrorKind::Message("openssl feature not enabled").into()),
    }
  }

  pub fn to_vec(&self) -> Vec<u8> {
    match *self {
      #[cfg(feature = "openssl")]
      KeyPair::RSA{ref pkey} => {
        let mut bytes: Vec<u8> = Vec::new();
        let rsa: OpenSslRsa = pkey.rsa().expect("pkey should have been initialized with RSA");

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
      #[cfg(feature = "openssl")]
      KeyPair::ECDSA{} => {
        let mut bytes: Vec<u8> = Vec::new();
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
      KeyPair::RSA{ref pkey} => {
        let mut signer = Signer::new(DigestType::from(algorithm).to_hash(), &pkey).unwrap();
        try!(signer.update(&hash));
        signer.finish().map_err(|e| e.into())
      },
      #[cfg(feature = "openssl")]
      KeyPair::ECDSA{} => {
        // FIXME
        Err(DnsSecErrorKind::Message("not implemented").into())
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
      KeyPair::RSA{ref pkey} => {
        let mut verifier = Verifier::new(DigestType::from(algorithm).to_hash(), &pkey).unwrap();
        try!(verifier.update(hash));
        verifier.finish(signature)
                .map_err(|e| e.into())
                .and_then(|b| if b { Ok(()) }
                              else { Err(DnsSecErrorKind::Message("could not verify").into()) })
      },
      #[cfg(feature = "openssl")]
      KeyPair::ECDSA{} => {
        // FIXME
        Err(DnsSecErrorKind::Message("not implemented").into())
      }
    }
  }
}

#[cfg(feature = "openssl")]
#[test]
fn test_hashing() {
  use ::rr::dnssec::Algorithm;
  use openssl::rsa;

  let bytes = b"www.example.com";
  let rsa = rsa::Rsa::generate(2048).unwrap();
  let key = KeyPair::from_rsa(rsa).unwrap();

  for algorithm in &[Algorithm::RSASHA1,
                     Algorithm::RSASHA256,
                     Algorithm::RSASHA1NSEC3SHA1,
                     Algorithm::RSASHA512] {
    let sig = key.sign(*algorithm, bytes).unwrap();
    assert!(key.verify(*algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
  }
}
