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
use openssl::bn::BigNumContext;
#[cfg(feature = "openssl")]
use openssl::ec::{EcGroup, EcKey, POINT_CONVERSION_UNCOMPRESSED};
#[cfg(feature = "openssl")]
use openssl::nid;

#[cfg(feature = "ring")]
use ring::rand;
#[cfg(feature = "ring")]
use ring::signature::{Ed25519KeyPair, EdDSAParameters, VerificationAlgorithm};
#[cfg(feature = "ring")]
use untrusted::Input;

use error::*;
use rr::Name;
use rr::dnssec::{Algorithm, DigestType, PublicKey};
#[cfg(feature = "ring")]
use rr::dnssec::public_key::Ed25519;
use rr::rdata::{DNSKEY, DS, KEY};

/// A public and private key pair, the private portion is not required.
///
/// This supports all the various public/private keys which TRust-DNS is capable of using. Given
///  differing features, some key types may not be available. The `openssl` feature will enable RSA and EC
///  (P256 and P384). The `ring` feature enables ED25519, in the future, Ring will also be used for other keys.
pub enum KeyPair {
    /// RSA keypair, supported by OpenSSL
    #[cfg(feature = "openssl")]
    RSA(PKey),
    /// Ellyptic curve keypair, supported by OpenSSL
    #[cfg(feature = "openssl")]
    EC(PKey),
    /// ED25519 ecryption and hash defined keypair
    #[cfg(feature = "ring")]
    ED25519(Ed25519KeyPair),
}

impl KeyPair {
    /// Creates an RSA type keypair.
    #[cfg(feature = "openssl")]
    pub fn from_rsa(rsa: OpenSslRsa) -> DnsSecResult<Self> {
        PKey::from_rsa(rsa)
            .map(|pkey| KeyPair::RSA(pkey))
            .map_err(|e| e.into())
    }

    /// Given a know pkey of an RSA key, return the wrapped keypair
    #[cfg(feature = "openssl")]
    pub fn from_rsa_pkey(pkey: PKey) -> Self {
        KeyPair::RSA(pkey)
    }

    /// Creates an EC, elliptic curve, type keypair, only P256 or P384 are supported.
    #[cfg(feature = "openssl")]
    pub fn from_ec_key(ec_key: EcKey) -> DnsSecResult<Self> {
        PKey::from_ec_key(ec_key)
            .map(|pkey| KeyPair::EC(pkey))
            .map_err(|e| e.into())
    }

    /// Given a know pkey of an EC key, return the wrapped keypair
    #[cfg(feature = "openssl")]
    pub fn from_ec_pkey(pkey: PKey) -> Self {
        KeyPair::EC(pkey)
    }

    /// Creates an ED25519 keypair.
    #[cfg(feature = "ring")]
    pub fn from_ed25519(ed_key: Ed25519KeyPair) -> Self {
        KeyPair::ED25519(ed_key)
    }

    /// Converts this keypair to the DNS binary form of the public_key.
    ///
    /// If there is a private key associated with this keypair, it will not be included in this
    ///  format. Only the public key material will be included.
    pub fn to_public_bytes(&self) -> DnsSecResult<Vec<u8>> {
        match *self {
            // see from_vec() RSA sections for reference
            #[cfg(feature = "openssl")]
            KeyPair::RSA(ref pkey) => {
                let mut bytes: Vec<u8> = Vec::new();
                // TODO: make these expects a try! and Err()
                let rsa: OpenSslRsa = pkey.rsa()
                    .expect("pkey should have been initialized with RSA");

                // this is to get us access to the exponent and the modulus
                // TODO: make these expects a try! and Err()
                let e: Vec<u8> = rsa.e()
                    .expect("RSA should have been initialized")
                    .to_vec();
                // TODO: make these expects a try! and Err()
                let n: Vec<u8> = rsa.n()
                    .expect("RSA should have been initialized")
                    .to_vec();

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
            }
            // see from_vec() ECDSA sections for reference
            #[cfg(feature = "openssl")]
            KeyPair::EC(ref pkey) => {
                // TODO: make these expects a try! and Err()
                let ec_key: EcKey = pkey.ec_key()
                    .expect("pkey should have been initialized with EC");
                ec_key
                    .group()
                    .and_then(|group| ec_key.public_key().map(|point| (group, point)))
                    .ok_or(DnsSecErrorKind::Message("missing group or point on ec_key").into())
                    .and_then(|(group, point)| {
                        BigNumContext::new()
                            .and_then(|mut ctx| {
                                          point.to_bytes(group,
                                                         POINT_CONVERSION_UNCOMPRESSED,
                                                         &mut ctx)
                                      })
                            .map_err(|e| e.into())
                    })
            }
            #[cfg(feature = "ring")]
            KeyPair::ED25519(ref ed_key) => Ok(ed_key.public_key_bytes().to_vec()),
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl or ring feature(s) not enabled").into()),
        }
    }

    /// The key tag is calculated as a hash to more quickly lookup a DNSKEY.
    ///
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035), DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987
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
    pub fn key_tag(&self) -> DnsSecResult<u16> {
        let mut ac: usize = 0;

        for (i, k) in try!(self.to_public_bytes()).iter().enumerate() {
            ac += if i & 0x0001 == 0x0001 {
                *k as usize
            } else {
                (*k as usize) << 8
            };
        }

        ac += (ac >> 16) & 0xFFFF;
        return Ok((ac & 0xFFFF) as u16); // this is unnecessary, no?
    }

    /// Creates a Record that represents the public key for this Signer
    ///
    /// # Arguments
    ///
    /// * `algorithm` - algorithm of the DNSKEY
    ///
    /// # Return
    ///
    /// the DNSKEY record data
    pub fn to_dnskey(&self, algorithm: Algorithm) -> DnsSecResult<DNSKEY> {
        self.to_public_bytes()
            .map(|bytes| DNSKEY::new(true, true, false, algorithm, bytes))
    }

    /// Convert this keypair into a KEY record type for usage with SIG0
    ///
    /// # Arguments
    ///
    /// * `algorithm` - algorithm of the KEY
    ///
    /// # Return
    ///
    /// the KEY record data
    pub fn to_sig0key(&self, algorithm: Algorithm) -> DnsSecResult<KEY> {
        self.to_public_bytes()
            .map(|bytes| {
                     KEY::new(Default::default(),
                              Default::default(),
                              Default::default(),
                              Default::default(),
                              algorithm,
                              bytes)
                 })
    }

    /// Creates a DS record for this KeyPair associated to the given name
    ///
    /// # Arguments
    ///
    /// * `name` - name of the DNSKEY record covered by the new DS record
    /// * `algorithm` - the algorithm of the DNSKEY
    /// * `digest_type` - the digest_type used to
    pub fn to_ds(&self,
                 name: &Name,
                 algorithm: Algorithm,
                 digest_type: DigestType)
                 -> DnsSecResult<DS> {
        self.to_dnskey(algorithm)
            .and_then(|dnskey| self.key_tag().map(|key_tag| (key_tag, dnskey)))
            .and_then(|(key_tag, dnskey)| {
                          dnskey
                              .to_digest(name, digest_type)
                              .map(|digest| (key_tag, digest))
                      })
            .map(|(key_tag, digest)| DS::new(key_tag, algorithm, digest_type, digest.to_vec()))
    }

    /// Signs a hash.
    ///
    /// This will panic if the `key` is not a private key and can be used for signing.
    ///
    /// # Arguments
    ///
    /// * `message` - the message bytes to be signed, see `hash_rrset`.
    ///
    /// # Return value
    ///
    /// The signature, ready to be stored in an `RData::RRSIG`.
    #[allow(unused)]
    pub fn sign(&self, algorithm: Algorithm, message: &[u8]) -> DnsSecResult<Vec<u8>> {
        match *self {
            #[cfg(feature = "openssl")]
            KeyPair::RSA(ref pkey) |
            KeyPair::EC(ref pkey) => {
                let digest_type = try!(DigestType::from(algorithm).to_openssl_digest());
                let mut signer = Signer::new(digest_type, &pkey).unwrap();
                try!(signer.update(&message));
                signer.finish().map_err(|e| e.into())
            }
            #[cfg(feature = "ring")]
            KeyPair::ED25519(ref ed_key) => Ok(ed_key.sign(message).as_ref().to_vec()),
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// Generates a new private and public key pair for the specified algorithm.
    ///
    /// RSA keys are hardcoded to 2048bits at the moment. Other keys have predefined sizes.
    pub fn generate(algorithm: Algorithm) -> DnsSecResult<Self> {
        match algorithm {
            #[cfg(feature = "openssl")]
            Algorithm::RSASHA1 |
            Algorithm::RSASHA1NSEC3SHA1 |
            Algorithm::RSASHA256 |
            Algorithm::RSASHA512 => {
                // TODO: the only keysize right now, would be better for people to use other algorithms...
                OpenSslRsa::generate(2048)
                    .map_err(|e| e.into())
                    .and_then(|rsa| KeyPair::from_rsa(rsa))
            }
            #[cfg(feature = "openssl")]
            Algorithm::ECDSAP256SHA256 => {
                EcGroup::from_curve_name(nid::SECP256K1)
                    .and_then(|group| EcKey::generate(&group))
                    .map_err(|e| e.into())
                    .and_then(|ec_key| KeyPair::from_ec_key(ec_key))
            }
            #[cfg(feature = "openssl")]
            Algorithm::ECDSAP384SHA384 => {
                EcGroup::from_curve_name(nid::SECP384R1)
                    .and_then(|group| EcKey::generate(&group))
                    .map_err(|e| e.into())
                    .and_then(|ec_key| KeyPair::from_ec_key(ec_key))
            }
            #[cfg(feature = "ring")]
            Algorithm::ED25519 => {
                Err(DnsSecErrorKind::Message("use generate_pkcs8 for generating private key and encoding").into())
            }
            #[cfg(not(all(feature = "openssl", feature = "ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// Generates a key, securing it with pkcs8
    #[cfg(feature = "ring")]
    pub fn generate_pkcs8(algorithm: Algorithm) -> DnsSecResult<Vec<u8>> {
        match algorithm {
            #[cfg(feature = "openssl")]
            Algorithm::RSASHA1 |
            Algorithm::RSASHA1NSEC3SHA1 |
            Algorithm::RSASHA256 |
            Algorithm::RSASHA512 => {
                Err(DnsSecErrorKind::Message("openssl does not yet support pkcs8").into())
            }
            #[cfg(feature = "openssl")]
            Algorithm::ECDSAP256SHA256 => {
                Err(DnsSecErrorKind::Message("openssl does not yet support pkcs8").into())
            }
            #[cfg(feature = "openssl")]
            Algorithm::ECDSAP384SHA384 => {
                Err(DnsSecErrorKind::Message("openssl does not yet support pkcs8").into())
            }
            #[cfg(feature = "ring")]
            Algorithm::ED25519 => {
                let rng = rand::SystemRandom::new();
                Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|e| e.into())
                    .map(|pkcs8_bytes| pkcs8_bytes.to_vec())
            }
            #[cfg(not(all(feature = "openssl", feature = "ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }
}

impl PublicKey for KeyPair {
    fn public_bytes(&self) -> &[u8] {
        // FIXME: don't actually need access to the public key bytes?
        unimplemented!()
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> DnsSecResult<()> {
        match *self {
            #[cfg(feature = "openssl")]
            KeyPair::RSA(ref pkey) |
            KeyPair::EC(ref pkey) => {
                let digest_type = try!(DigestType::from(algorithm).to_openssl_digest());
                let mut verifier = Verifier::new(digest_type, &pkey).unwrap();
                try!(verifier.update(message));
                verifier
                    .finish(signature)
                    .map_err(|e| e.into())
                    .and_then(|b| if b {
                                  Ok(())
                              } else {
                                  Err(DnsSecErrorKind::Message("could not verify").into())
                              })
            }
            #[cfg(feature = "ring")]
            KeyPair::ED25519(ref ed_key) => {
                let pub_key = Ed25519::from_public_bytes(&ed_key.public_key_bytes())?;
                pub_key
                    .verify(algorithm, message, signature)
                    .map_err(|e| e.into())
            }
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
            _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }
}

#[cfg(any(feature = "openssl", feature = "ring"))]
#[cfg(test)]
mod tests {
    use rr::dnssec::*;

    #[cfg(feature = "openssl")]
    #[test]
    fn test_rsa_hashing() {
        hash_test(Algorithm::RSASHA256, KeyFormat::Der);
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_ec_hashing_p256() {
        hash_test(Algorithm::ECDSAP256SHA256, KeyFormat::Der);
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_ec_hashing_p384() {
        hash_test(Algorithm::ECDSAP384SHA384, KeyFormat::Der);
    }

    #[cfg(feature = "ring")]
    #[test]
    fn test_ed25519() {
        hash_test(Algorithm::ED25519, KeyFormat::Pkcs8);
    }

    fn hash_test(algorithm: Algorithm, key_format: KeyFormat) {
        let bytes = b"www.example.com";

        // TODO: convert to stored keys...
        let key = key_format
            .decode_key(&key_format.generate_and_encode(algorithm, None).unwrap(),
                        None,
                        algorithm)
            .unwrap();
        let neg = key_format
            .decode_key(&key_format.generate_and_encode(algorithm, None).unwrap(),
                        None,
                        algorithm)
            .unwrap();

        let sig = key.sign(algorithm, bytes).unwrap();
        assert!(key.verify(algorithm, bytes, &sig).is_ok(),
                "algorithm: {:?}",
                algorithm);
        assert!(!neg.verify(algorithm, bytes, &sig).is_ok(),
                "algorithm: {:?}",
                algorithm);
    }
}