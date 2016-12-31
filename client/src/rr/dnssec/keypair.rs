// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "openssl")] use openssl::rsa::Rsa as OpenSslRsa;
#[cfg(feature = "openssl")] use openssl::sign::{Signer, Verifier};
#[cfg(feature = "openssl")] use openssl::pkey::PKey;
#[cfg(feature = "openssl")] use openssl::bn::{BigNum, BigNumContext};
#[cfg(feature = "openssl")] use openssl::ec::{EcGroup, EcKey, EcPoint, POINT_CONVERSION_UNCOMPRESSED};
#[cfg(feature = "openssl")] use openssl::nid;

use ::error::*;
use ::rr::{Name, RData, Record, RecordType};
use ::rr::dnssec::{Algorithm, DigestType};
use ::rr::rdata::DNSKEY;

/// A public and private key pair.
pub enum KeyPair {
  #[cfg(feature = "openssl")]
  RSA { pkey: PKey },
  #[cfg(feature = "openssl")]
  EC { pkey: PKey },
}

impl KeyPair {
  pub fn from_rsa(rsa: OpenSslRsa) -> DnsSecResult<Self> {
    PKey::from_rsa(rsa).map(|pkey| KeyPair::RSA{pkey: pkey}).map_err(|e| e.into())
  }

  pub fn from_ec_key(ec_key: EcKey) -> DnsSecResult<Self> {
    PKey::from_ec_key(ec_key).map(|pkey| KeyPair::EC{pkey: pkey}).map_err(|e| e.into())
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
      Algorithm::ECDSAP256SHA256 => {
        // RFC 6605                    ECDSA for DNSSEC                  April 2012
        //        4.  DNSKEY and RRSIG Resource Records for ECDSA
        //
        //   ECDSA public keys consist of a single value, called "Q" in FIPS
        //   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
        //   uncompressed form of a curve point, "x | y".
        //
        //   The ECDSA signature is the combination of two non-negative integers,
        //   called "r" and "s" in FIPS 186-3.  The two integers, each of which is
        //   formatted as a simple octet string, are combined into a single longer
        //   octet string for DNSSEC as the concatenation "r | s".  (Conversion of
        //   the integers to bit strings is described in Section C.2 of FIPS
        //   186-3.)  For P-256, each integer MUST be encoded as 32 octets; for
        //   P-384, each integer MUST be encoded as 48 octets.
        //
        //   The algorithm numbers associated with the DNSKEY and RRSIG resource
        //   records are fully defined in the IANA Considerations section.  They
        //   are:
        //
        //   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-256 curve and
        //      SHA-256 use the algorithm number 13.
        //
        //   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-384 curve and
        //      SHA-384 use the algorithm number 14.
        //
        //   Conformant implementations that create records to be put into the DNS
        //   MUST implement signing and verification for both of the above
        //   algorithms.  Conformant DNSSEC verifiers MUST implement verification
        //   for both of the above algorithms.
        EcGroup::from_curve_name(nid::SECP256K1)
                .and_then(|group| BigNumContext::new().map(|ctx| (group, ctx)))
                .and_then(|(group, mut ctx)| EcPoint::from_bytes(&group, public_key, &mut ctx).map(|point| (group, point) ))
                .and_then(|(group, point)| EcKey::from_public_key(&group, &point))
                .and_then(|ec_key| PKey::from_ec_key(ec_key) )
                .map(|pkey| KeyPair::EC{ pkey: pkey })
                .map_err(|e| e.into())
      },
      Algorithm::ECDSAP384SHA384 => {
        // see above Algorithm::ECDSAP256SHA256 for reference
        EcGroup::from_curve_name(nid::SECP384R1)
                .and_then(|group| BigNumContext::new().map(|ctx| (group, ctx)))
                .and_then(|(group, mut ctx)| EcPoint::from_bytes(&group, public_key, &mut ctx).map(|point| (group, point) ))
                .and_then(|(group, point)| EcKey::from_public_key(&group, &point))
                .and_then(|ec_key| PKey::from_ec_key(ec_key) )
                .map(|pkey| KeyPair::EC{ pkey: pkey })
                .map_err(|e| e.into())
      },
      // _ => Err(DecodeErrorKind::Message("openssl feature not enabled").into()),
    }
  }

  /// Converts this keypair to the DNS binary form of the public_key.
  ///
  /// If there is a private key associated with this keypair, it will not be included in this
  ///  format. Only the public key material will be included.
  pub fn to_vec(&self) -> DnsSecResult<Vec<u8>> {
    match *self {
      // see from_vec() RSA sections for reference
      #[cfg(feature = "openssl")]
      KeyPair::RSA{ref pkey} => {
        let mut bytes: Vec<u8> = Vec::new();
        // TODO: make these expects a try! and Err()
        let rsa: OpenSslRsa = pkey.rsa().expect("pkey should have been initialized with RSA");

        // this is to get us access to the exponent and the modulus
        // TODO: make these expects a try! and Err()
        let e: Vec<u8> = rsa.e().expect("RSA should have been initialized").to_vec();
        // TODO: make these expects a try! and Err()
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

        Ok(bytes)
      },
      // see from_vec() ECDSA sections for reference
      #[cfg(feature = "openssl")]
      KeyPair::EC{ref pkey} => {
        // TODO: make these expects a try! and Err()
        let ec_key: EcKey = pkey.ec_key().expect("pkey should have been initialized with EC");
        ec_key.group()
              .and_then(|group| ec_key.public_key().map(|point| (group, point) ))
              .ok_or(DnsSecErrorKind::Message("missing group or point on ec_key").into())
              .and_then(|(group, point)| BigNumContext::new()
                                                       .and_then(|mut ctx| point.to_bytes(group, POINT_CONVERSION_UNCOMPRESSED, &mut ctx))
                                                       .map_err(|e| e.into()) )
      },
      #[cfg(not(feature = "openssl"))]
      _ => vec![],
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
  pub fn to_dnskey(&self, name: Name, ttl: u32, algorithm: Algorithm) -> DnsSecResult<Record> {
    self.to_vec()
        .map(|bytes| {
          let mut record = Record::with(name.clone(), RecordType::DNSKEY, ttl);
          record.rdata(RData::DNSKEY(DNSKEY::new(true, true, false, algorithm, bytes)));
          record
        })
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
      KeyPair::RSA{ref pkey} | KeyPair::EC{ref pkey} => {
        let mut signer = Signer::new(DigestType::from(algorithm).to_hash(), &pkey).unwrap();
        try!(signer.update(&hash));
        signer.finish().map_err(|e| e.into())
      },
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
      KeyPair::RSA{ref pkey} | KeyPair::EC{ref pkey} => {
        let mut verifier = Verifier::new(DigestType::from(algorithm).to_hash(), &pkey).unwrap();
        try!(verifier.update(hash));
        verifier.finish(signature)
                .map_err(|e| e.into())
                .and_then(|b| if b { Ok(()) }
                              else { Err(DnsSecErrorKind::Message("could not verify").into()) })
      },
    }
  }
}

#[cfg(feature = "openssl")]
#[test]
fn test_rsa_hashing() {
  use ::rr::dnssec::Algorithm;
  use openssl::rsa;

  let bytes = b"www.example.com";
  let key = rsa::Rsa::generate(2048)
                     .map_err(|e| e.into())
                     .and_then(|rsa| KeyPair::from_rsa(rsa))
                     .unwrap();
  let neg = rsa::Rsa::generate(2048)
                     .map_err(|e| e.into())
                     .and_then(|rsa| KeyPair::from_rsa(rsa))
                     .unwrap();

  for algorithm in &[Algorithm::RSASHA1,
                     Algorithm::RSASHA256,
                     Algorithm::RSASHA1NSEC3SHA1,
                     Algorithm::RSASHA512] {
    let sig = key.sign(*algorithm, bytes).unwrap();
    assert!(key.verify(*algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
    assert!(!neg.verify(*algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
  }
}

#[cfg(feature = "openssl")]
#[test]
fn test_ec_hashing_p256() {
  use ::rr::dnssec::Algorithm;
  use openssl::ec;
  let algorithm = Algorithm::ECDSAP256SHA256;
  let bytes = b"www.example.com";
  let key = EcGroup::from_curve_name(nid::SECP256K1)
                    .and_then(|group| ec::EcKey::generate(&group))
                    .map_err(|e| e.into())
                    .and_then(|ec_key| KeyPair::from_ec_key(ec_key))
                    .unwrap();
  let neg = EcGroup::from_curve_name(nid::SECP256K1)
                    .and_then(|group| ec::EcKey::generate(&group))
                    .map_err(|e| e.into())
                    .and_then(|ec_key| KeyPair::from_ec_key(ec_key))
                    .unwrap();

  let sig = key.sign(algorithm, bytes).unwrap();
  assert!(key.verify(algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
  assert!(!neg.verify(algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
}

#[cfg(feature = "openssl")]
#[test]
fn test_ec_hashing_p384() {
  use ::rr::dnssec::Algorithm;
  use openssl::ec;
  let algorithm = Algorithm::ECDSAP384SHA384;
  let bytes = b"www.example.com";
  let key = EcGroup::from_curve_name(nid::SECP384R1)
                    .and_then(|group| ec::EcKey::generate(&group))
                    .map_err(|e| e.into())
                    .and_then(|ec_key| KeyPair::from_ec_key(ec_key))
                    .unwrap();
  let neg = EcGroup::from_curve_name(nid::SECP384R1)
                    .and_then(|group| ec::EcKey::generate(&group))
                    .map_err(|e| e.into())
                    .and_then(|ec_key| KeyPair::from_ec_key(ec_key))
                    .unwrap();

  let sig = key.sign(algorithm, bytes).unwrap();
  assert!(key.verify(algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
  assert!(!neg.verify(algorithm, bytes, &sig).is_ok(), "algorithm: {:?}", algorithm);
}
