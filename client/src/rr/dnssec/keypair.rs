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
use openssl::bn::{BigNum, BigNumContext};
#[cfg(feature = "openssl")]
use openssl::ec::{EcGroup, EcKey, EcPoint, POINT_CONVERSION_UNCOMPRESSED};
#[cfg(feature = "openssl")]
use openssl::nid;

#[cfg(feature = "ring")]
use ring::rand;
#[cfg(feature = "ring")]
use ring::signature::{Ed25519KeyPair, Ed25519KeyPairBytes, EdDSAParameters, VerificationAlgorithm};
#[cfg(feature = "ring")]
use untrusted::Input;

use error::*;
use rr::Name;
use rr::dnssec::{Algorithm, DigestType};
use rr::rdata::{DNSKEY, DS};

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
    ED25519(Ed25519KeyPairBytes),
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
    pub fn from_ed25519(ed_key: Ed25519KeyPairBytes) -> Self {
        KeyPair::ED25519(ed_key)
    }

    /// Converts an array of bytes into a KeyPair, interpreting it based on the algorithm type.
    ///
    /// Formats for the public key are described in rfc3110, rfc6605, and
    ///  rfc-draft-ietf-curdle-dnskey-eddsa-03.
    ///
    /// # Arguments
    ///
    /// * `public_key` - the public key bytes formatted in BigEndian/NetworkByteOrder
    /// * `algorithm` - the Algorithm which is used to interpret the key
    pub fn from_public_bytes(public_key: &[u8], algorithm: Algorithm) -> DnsSecResult<Self> {
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
                if public_key.len() < 3 || public_key.len() > (4096 + 3) {
                    return Err(DnsSecErrorKind::Message("bad public key").into());
                }
                let mut num_exp_len_octs = 1;
                let mut len: u16 = public_key[0] as u16;
                if len == 0 {
                    num_exp_len_octs = 3;
                    len = ((public_key[1] as u16) << 8) | (public_key[2] as u16)
                }
                let len = len; // demut

                // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
                let e = try!(BigNum::from_slice(&public_key[(num_exp_len_octs as usize)..
                                                 (len as usize + num_exp_len_octs)]));
                let n = try!(BigNum::from_slice(&public_key[(len as usize + num_exp_len_octs)..]));

                OpenSslRsa::from_public_components(n, e)
                    .map_err(|e| e.into())
                    .and_then(|rsa| Self::from_rsa(rsa))
            }
            #[cfg(feature = "openssl")]
      Algorithm::ECDSAP256SHA256 => {
                // RFC 6605                    ECDSA for DNSSEC                  April 2012
                //
                //   4.  DNSKEY and RRSIG Resource Records for ECDSA
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
                // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
                .and_then(|(group, mut ctx)| EcPoint::from_bytes(&group, public_key, &mut ctx).map(|point| (group, point) ))
                .and_then(|(group, point)| EcKey::from_public_key(&group, &point))
                .and_then(|ec_key| PKey::from_ec_key(ec_key) )
                .map(|pkey| KeyPair::EC(pkey))
                .map_err(|e| e.into())
            }
            #[cfg(feature = "openssl")]
      Algorithm::ECDSAP384SHA384 => {
                // see above Algorithm::ECDSAP256SHA256 for reference
                EcGroup::from_curve_name(nid::SECP384R1)
                .and_then(|group| BigNumContext::new().map(|ctx| (group, ctx)))
                // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
                .and_then(|(group, mut ctx)| EcPoint::from_bytes(&group, public_key, &mut ctx).map(|point| (group, point) ))
                .and_then(|(group, point)| EcKey::from_public_key(&group, &point))
                .and_then(|ec_key| PKey::from_ec_key(ec_key) )
                .map(|pkey| KeyPair::EC(pkey))
                .map_err(|e| e.into())
            }
            #[cfg(feature = "ring")]
      Algorithm::ED25519 => {
                // Internet-Draft              EdDSA for DNSSEC               December 2016
                //
                //  An Ed25519 public key consists of a 32-octet value, which is encoded
                //  into the Public Key field of a DNSKEY resource record as a simple bit
                //  string.  The generation of a public key is defined in Section 5.1.5
                //  in [I-D.irtf-cfrg-eddsa].
                //
                // **NOTE: not specified in the RFC is the byte order, assuming it is
                //  BigEndian/NetworkByteOrder.
                if public_key.len() != 32 {
                    return Err(DnsSecErrorKind::Msg(format!("expected 32 byte public_key: {}",
                                                            public_key.len()))
                                       .into());
                }

                // these are LittleEndian encoded bytes... we need to special case
                //  serialzation/deserialization for endianess. why, Intel, why...
                let mut public_key = public_key.to_vec();
                public_key.reverse();

                let mut ed_key_pair = Ed25519KeyPairBytes {
                    private_key: [0_u8; 32],
                    public_key: [0_u8; 32],
                };

                ed_key_pair.public_key.copy_from_slice(&public_key);
                Ok(KeyPair::ED25519(ed_key_pair))
            }
            #[cfg(not(all(feature = "openssl", feature = "ring")))]
      _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
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
      KeyPair::ED25519(ref ed_key) => {
                // this is "little endian" encoded bytes... we need to special case
                //  serialzation/deserialization for endianess. why, Intel, why...
                let mut pub_key = ed_key.public_key.to_vec();
                pub_key.reverse();
                Ok(pub_key)
            }
            // #[cfg(not(all(feature = "openssl", feature = "ring")))]
            // _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
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
    /// * `name` - name of the entity associated with this DNSKEY
    /// * `ttl` - the time to live for this DNSKEY
    ///
    /// # Return
    ///
    /// the DNSKEY record data
    // pub fn to_dnskey(&self, name: Name, ttl: u32, algorithm: Algorithm) -> DnsSecResult<DNSKEY> {
    pub fn to_dnskey(&self, algorithm: Algorithm) -> DnsSecResult<DNSKEY> {
        self.to_public_bytes()
            .map(|bytes| DNSKEY::new(true, true, false, algorithm, bytes))
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
            .map(|(key_tag, digest)| DS::new(key_tag, algorithm, digest_type, digest))
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
      KeyPair::ED25519(ref ed_key) => {
                Ed25519KeyPair::from_bytes(&ed_key.private_key, &ed_key.public_key)
                    .map_err(|_| {
                                 DnsSecErrorKind::Message("something is wrong with the keys").into()
                             })
                    .map(|ed_key| ed_key.sign(message).as_slice().to_vec())
            }
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
      _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// Verifies the hash matches the signature with the current `key`.
    ///
    /// # Arguments
    ///
    /// * `message` - the message to be validated, see `hash_rrset`
    /// * `signature` - the signature to use to verify the hash, extracted from an `RData::RRSIG`
    ///                 for example.
    ///
    /// # Return value
    ///
    /// True if and only if the signature is valid for the hash. This will always return
    /// false if the `key`.
    pub fn verify(&self,
                  algorithm: Algorithm,
                  message: &[u8],
                  signature: &[u8])
                  -> DnsSecResult<()> {
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
                let public_key = Input::from(&ed_key.public_key);
                let message = Input::from(message);
                let signature = Input::from(signature);
                EdDSAParameters {}
                    .verify(public_key, message, signature)
                    .map_err(|e| e.into())
            }
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
      _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// The KeyPair, with private key, converted to binary form.
    ///
    /// Generally the format is will be in PEM, with the exception of ED25519, which is
    ///  currently little endian `32 private key bytes | 32 public key bytes`.
    pub fn to_private_bytes(&self) -> DnsSecResult<Vec<u8>> {
        match *self {
            #[cfg(feature = "openssl")]
      KeyPair::RSA(ref pkey) |
            KeyPair::EC(ref pkey) => pkey.private_key_to_pem().map_err(|e| e.into()),
            #[cfg(feature = "ring")]
      KeyPair::ED25519(ref ed_key) => {
                let mut vec = Vec::with_capacity(ed_key.private_key.len() +
                                                 ed_key.public_key.len());

                vec.extend_from_slice(&ed_key.private_key);
                vec.extend_from_slice(&ed_key.public_key);
                Ok(vec)
            }
            #[cfg(not(any(feature = "openssl", feature = "ring")))]
      _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }

    /// Creates a KeyPair for the specified algorithm with the associated bytes
    ///
    /// Generally the format is expected to be in PEM, with the exception of ED25519, which is
    ///  currently little endian `32 private key bytes | 32 public key bytes`.
    pub fn from_private_bytes(algorithm: Algorithm, bytes: &[u8]) -> DnsSecResult<Self> {
        match algorithm {
            #[cfg(feature = "openssl")]
      Algorithm::RSASHA1 |
            Algorithm::RSASHA1NSEC3SHA1 |
            Algorithm::RSASHA256 |
            Algorithm::RSASHA512 => {
                let rsa = try!(OpenSslRsa::private_key_from_pem(bytes));
                KeyPair::from_rsa(rsa)
            }
            #[cfg(feature = "openssl")]
      Algorithm::ECDSAP256SHA256 |
            Algorithm::ECDSAP384SHA384 => {
                let ec = try!(EcKey::private_key_from_pem(bytes));
                KeyPair::from_ec_key(ec)
            }
            #[cfg(feature = "ring")]
      Algorithm::ED25519 => {
                let mut private_key = [0u8; 32];
                let mut public_key = [0u8; 32];

                if bytes.len() != 64 {
                    return Err(DnsSecErrorKind::Msg(format!("expected 64 bytes: {}", bytes.len()))
                                   .into());
                }

                private_key.copy_from_slice(&bytes[..32]);
                public_key.copy_from_slice(&bytes[32..]);

                Ok(KeyPair::from_ed25519(Ed25519KeyPairBytes {
                                             private_key: private_key,
                                             public_key: public_key,
                                         }))
            }
            #[cfg(not(all(feature = "openssl", feature = "ring")))]
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
                let rng = rand::SystemRandom::new();
                Ed25519KeyPair::generate_serializable(&rng)
                    .map_err(|e| e.into())
                    .map(|(_, key)| KeyPair::from_ed25519(key))
            }
            #[cfg(not(all(feature = "openssl", feature = "ring")))]
      _ => Err(DnsSecErrorKind::Message("openssl nor ring feature(s) not enabled").into()),
        }
    }
}

#[cfg(feature = "openssl")]
#[test]
fn test_rsa_hashing() {
    hash_test(Algorithm::RSASHA256);
}

#[cfg(feature = "openssl")]
#[test]
fn test_ec_hashing_p256() {
    hash_test(Algorithm::ECDSAP256SHA256);
}

#[cfg(feature = "openssl")]
#[test]
fn test_ec_hashing_p384() {
    hash_test(Algorithm::ECDSAP384SHA384);
}

#[cfg(feature = "ring")]
#[test]
fn test_ed25519() {
    hash_test(Algorithm::ED25519);
}

#[cfg(test)]
fn hash_test(algorithm: Algorithm) {
    let bytes = b"www.example.com";

    let key = KeyPair::generate(algorithm).unwrap();
    let neg = KeyPair::generate(algorithm).unwrap();

    let sig = key.sign(algorithm, bytes).unwrap();
    assert!(key.verify(algorithm, bytes, &sig).is_ok(),
            "algorithm: {:?}",
            algorithm);
    assert!(!neg.verify(algorithm, bytes, &sig).is_ok(),
            "algorithm: {:?}",
            algorithm);
}


#[cfg(feature = "openssl")]
#[test]
fn test_to_from_public_key_rsa() {
    to_from_public_key_test(Algorithm::RSASHA256);
}

#[cfg(feature = "openssl")]
#[test]
fn test_to_from_public_key_ec_p256() {
    to_from_public_key_test(Algorithm::ECDSAP256SHA256);
}

#[cfg(feature = "openssl")]
#[test]
fn test_to_from_public_key_ec_p384() {
    to_from_public_key_test(Algorithm::ECDSAP384SHA384);
}

#[cfg(feature = "ring")]
#[test]
fn test_to_from_public_key_ed25519() {
    to_from_public_key_test(Algorithm::ED25519);
}

#[cfg(test)]
fn to_from_public_key_test(algorithm: Algorithm) {
    let key = KeyPair::generate(algorithm).unwrap();

    assert!(key.to_public_bytes()
                .and_then(|bytes| KeyPair::from_public_bytes(&bytes, algorithm))
                .is_ok());
}

#[cfg(feature = "openssl")]
#[test]
fn test_serialization_ec() {
    test_serialization(Algorithm::ECDSAP256SHA256);
}

#[cfg(feature = "ring")]
#[test]
fn test_serialization_ed25519() {
    test_serialization(Algorithm::ED25519);
}

#[cfg(feature = "openssl")]
#[test]
fn test_serialization_rsa() {
    test_serialization(Algorithm::RSASHA256);
}

#[cfg(test)]
fn test_serialization(algorithm: Algorithm) {
    let key = KeyPair::generate(algorithm).unwrap();

    assert!(KeyPair::from_private_bytes(algorithm, &key.to_private_bytes().unwrap()).is_ok());
}
