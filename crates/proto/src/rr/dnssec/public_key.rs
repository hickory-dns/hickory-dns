// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types
#[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
use std::marker::PhantomData;

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use openssl::bn::BigNum;
#[cfg(feature = "dnssec-openssl")]
use openssl::bn::BigNumContext;
#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use openssl::ec::{EcGroup, EcPoint};
#[cfg(feature = "dnssec-openssl")]
use openssl::ec::{EcKey, PointConversionForm};
#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use openssl::nid::Nid;
#[cfg(feature = "dnssec-openssl")]
use openssl::pkey::HasPublic;
#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use openssl::pkey::{PKey, Public};
#[cfg(feature = "dnssec-openssl")]
use openssl::rsa::Rsa as OpenSslRsa;
#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use openssl::sign::Verifier;
#[cfg(feature = "dnssec-ring")]
use ring::signature::{self, ED25519_PUBLIC_KEY_LEN};

#[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
use super::ec_public_key::ECPublicKey;
#[allow(deprecated)]
use super::rdata::key::{KeyTrust, KeyUsage, Protocol, UpdateScope};
use super::rdata::{DNSKEY, DS, KEY};
#[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
use super::rsa_public_key::RSAPublicKey;
use super::{Algorithm, DigestType};
use crate::error::{DnsSecResult, ProtoResult};
use crate::rr::Name;

/// PublicKeys implement the ability to ideally be zero copy abstractions over public keys for verifying signed content.
///
/// In DNS the KEY and DNSKEY types are generally the RData types which store public key material.
pub trait PublicKey {
    /// Convert this keypair into a KEY record type for usage with SIG0
    /// with key type entity (`KeyUsage::Entity`).
    ///
    /// # Arguments
    ///
    /// * `algorithm` - algorithm of the KEY
    ///
    /// # Return
    ///
    /// the KEY record data
    fn to_sig0key(&self, algorithm: Algorithm) -> KEY {
        self.to_sig0key_with_usage(algorithm, KeyUsage::default())
    }

    /// Convert this keypair into a KEY record type for usage with SIG0
    /// with a given key (usage) type.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - algorithm of the KEY
    /// * `usage`     - the key type
    ///
    /// # Return
    ///
    /// the KEY record data
    fn to_sig0key_with_usage(&self, algorithm: Algorithm, usage: KeyUsage) -> KEY {
        KEY::new(
            KeyTrust::default(),
            usage,
            #[allow(deprecated)]
            UpdateScope::default(),
            Protocol::default(),
            algorithm,
            self.public_bytes().to_vec(),
        )
    }

    /// Creates a DS record for this KeyPair associated to the given name
    ///
    /// # Arguments
    ///
    /// * `name` - name of the DNSKEY record covered by the new DS record
    /// * `algorithm` - the algorithm of the DNSKEY
    /// * `digest_type` - the digest_type used to
    fn to_ds(
        &self,
        name: &Name,
        algorithm: Algorithm,
        digest_type: DigestType,
    ) -> DnsSecResult<DS> {
        let dnskey = self.to_dnskey(algorithm);
        Ok(DS::new(
            self.key_tag(),
            algorithm,
            digest_type,
            dnskey.to_digest(name, digest_type)?.as_ref().to_owned(),
        ))
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
    fn to_dnskey(&self, algorithm: Algorithm) -> DNSKEY {
        let bytes = self.public_bytes();
        DNSKEY::new(true, true, false, algorithm, bytes.to_owned())
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
    fn key_tag(&self) -> u16 {
        let mut ac = 0;

        for (i, k) in self.public_bytes().iter().enumerate() {
            ac += if i & 0x0001 == 0x0001 {
                *k as usize
            } else {
                (*k as usize) << 8
            };
        }

        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16 // this is unnecessary, no?
    }

    /// Returns the public bytes of the public key, in DNS format
    fn public_bytes(&self) -> &[u8];

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
    #[allow(unused)]
    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()>;
}

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
fn verify_with_pkey(
    pkey: &PKey<Public>,
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
) -> ProtoResult<()> {
    let digest_type = DigestType::from(algorithm).to_openssl_digest()?;
    let mut verifier = Verifier::new(digest_type, pkey)?;
    verifier.update(message)?;
    verifier
        .verify(signature)
        .map_err(Into::into)
        .and_then(|b| {
            if b {
                Ok(())
            } else {
                Err("could not verify".into())
            }
        })
}

/// Elyptic Curve public key type
#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
pub struct Ec<'k> {
    raw: &'k [u8],
    pkey: PKey<Public>,
}

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
impl<'k> Ec<'k> {
    /// ```text
    /// RFC 6605                    ECDSA for DNSSEC                  April 2012
    ///
    ///   4.  DNSKEY and RRSIG Resource Records for ECDSA
    ///
    ///   ECDSA public keys consist of a single value, called "Q" in FIPS
    ///   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
    ///   uncompressed form of a curve point, "x | y".
    ///
    ///   The ECDSA signature is the combination of two non-negative integers,
    ///   called "r" and "s" in FIPS 186-3.  The two integers, each of which is
    ///   formatted as a simple octet string, are combined into a single longer
    ///   octet string for DNSSEC as the concatenation "r | s".  (Conversion of
    ///   the integers to bit strings is described in Section C.2 of FIPS
    ///   186-3.)  For P-256, each integer MUST be encoded as 32 octets; for
    ///   P-384, each integer MUST be encoded as 48 octets.
    ///
    ///   The algorithm numbers associated with the DNSKEY and RRSIG resource
    ///   records are fully defined in the IANA Considerations section.  They
    ///   are:
    ///
    ///   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-256 curve and
    ///      SHA-256 use the algorithm number 13.
    ///
    ///   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-384 curve and
    ///      SHA-384 use the algorithm number 14.
    ///
    ///   Conformant implementations that create records to be put into the DNS
    ///   MUST implement signing and verification for both of the above
    ///   algorithms.  Conformant DNSSEC verifiers MUST implement verification
    ///   for both of the above algorithms.
    /// ```
    pub fn from_public_bytes(public_key: &'k [u8], algorithm: Algorithm) -> ProtoResult<Self> {
        let curve = match algorithm {
            Algorithm::ECDSAP256SHA256 => Nid::X9_62_PRIME256V1,
            Algorithm::ECDSAP384SHA384 => Nid::SECP384R1,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };
        // Key needs to be converted to OpenSSL format
        let k = ECPublicKey::from_unprefixed(public_key, algorithm)?;
        EcGroup::from_curve_name(curve)
            .and_then(|group| BigNumContext::new().map(|ctx| (group, ctx)))
            // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
            .and_then(|(group, mut ctx)| {
                EcPoint::from_bytes(&group, k.prefixed_bytes(), &mut ctx)
                    .map(|point| (group, point))
            })
            .and_then(|(group, point)| EcKey::from_public_key(&group, &point))
            .and_then(PKey::from_ec_key)
            .map_err(Into::into)
            .map(|pkey| Ec {
                raw: public_key,
                pkey,
            })
    }
}

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
fn asn1_emit_integer(output: &mut Vec<u8>, int: &[u8]) {
    assert!(!int.is_empty());
    output.push(0x02); // INTEGER
    if int[0] > 0x7f {
        output.push((int.len() + 1) as u8);
        output.push(0x00); // MSB must be zero
        output.extend(int);
        return;
    }
    // Trim leading zeros
    let mut pos = 0;
    while pos < int.len() {
        if int[pos] == 0 {
            if pos == int.len() - 1 {
                break;
            }
            pos += 1;
            continue;
        }
        if int[pos] > 0x7f {
            // We need to leave one 0x00 to make MSB zero
            pos -= 1;
        }
        break;
    }
    let int_output = &int[pos..];
    output.push(int_output.len() as u8);
    output.extend(int_output);
}

/// Convert raw DNSSEC ECDSA signature to ASN.1 DER format
#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
pub fn dnssec_ecdsa_signature_to_der(signature: &[u8]) -> ProtoResult<Vec<u8>> {
    if signature.is_empty() || signature.len() & 1 != 0 || signature.len() > 127 {
        return Err("invalid signature length".into());
    }
    let part_len = signature.len() / 2;
    // ASN.1 SEQUENCE: 0x30 [LENGTH]
    let mut signature_asn1 = vec![0x30, 0x00];
    asn1_emit_integer(&mut signature_asn1, &signature[..part_len]);
    asn1_emit_integer(&mut signature_asn1, &signature[part_len..]);
    signature_asn1[1] = (signature_asn1.len() - 2) as u8;
    Ok(signature_asn1)
}

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
impl<'k> PublicKey for Ec<'k> {
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        let signature_asn1 = dnssec_ecdsa_signature_to_der(signature)?;
        verify_with_pkey(&self.pkey, algorithm, message, &signature_asn1)
    }
}

/// Elyptic Curve public key type
#[cfg(feature = "dnssec-ring")]
pub type Ec = ECPublicKey;

#[cfg(feature = "dnssec-ring")]
impl Ec {
    /// ```text
    /// RFC 6605                    ECDSA for DNSSEC                  April 2012
    ///
    ///   4.  DNSKEY and RRSIG Resource Records for ECDSA
    ///
    ///   ECDSA public keys consist of a single value, called "Q" in FIPS
    ///   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
    ///   uncompressed form of a curve point, "x | y".
    ///
    ///   The ECDSA signature is the combination of two non-negative integers,
    ///   called "r" and "s" in FIPS 186-3.  The two integers, each of which is
    ///   formatted as a simple octet string, are combined into a single longer
    ///   octet string for DNSSEC as the concatenation "r | s".  (Conversion of
    ///   the integers to bit strings is described in Section C.2 of FIPS
    ///   186-3.)  For P-256, each integer MUST be encoded as 32 octets; for
    ///   P-384, each integer MUST be encoded as 48 octets.
    ///
    ///   The algorithm numbers associated with the DNSKEY and RRSIG resource
    ///   records are fully defined in the IANA Considerations section.  They
    ///   are:
    ///
    ///   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-256 curve and
    ///      SHA-256 use the algorithm number 13.
    ///
    ///   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-384 curve and
    ///      SHA-384 use the algorithm number 14.
    ///
    ///   Conformant implementations that create records to be put into the DNS
    ///   MUST implement signing and verification for both of the above
    ///   algorithms.  Conformant DNSSEC verifiers MUST implement verification
    ///   for both of the above algorithms.
    /// ```
    pub fn from_public_bytes(public_key: &[u8], algorithm: Algorithm) -> ProtoResult<Self> {
        Self::from_unprefixed(public_key, algorithm)
    }
}

#[cfg(feature = "dnssec-ring")]
impl PublicKey for Ec {
    fn public_bytes(&self) -> &[u8] {
        self.unprefixed_bytes()
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        // TODO: assert_eq!(algorithm, self.algorithm); once *ring* allows this.
        let alg = match algorithm {
            Algorithm::ECDSAP256SHA256 => &signature::ECDSA_P256_SHA256_FIXED,
            Algorithm::ECDSAP384SHA384 => &signature::ECDSA_P384_SHA384_FIXED,
            _ => return Err("only ECDSAP256SHA256 and ECDSAP384SHA384 are supported by Ec".into()),
        };
        let public_key = signature::UnparsedPublicKey::new(alg, self.prefixed_bytes());
        public_key.verify(message, signature).map_err(Into::into)
    }
}

/// Ed25519 Public key
#[cfg(feature = "dnssec-ring")]
pub struct Ed25519<'k> {
    raw: &'k [u8],
}

#[cfg(feature = "dnssec-ring")]
impl<'k> Ed25519<'k> {
    /// ```text
    ///  Internet-Draft              EdDSA for DNSSEC               December 2016
    ///
    ///  An Ed25519 public key consists of a 32-octet value, which is encoded
    ///  into the Public Key field of a DNSKEY resource record as a simple bit
    ///  string.  The generation of a public key is defined in Section 5.1.5
    ///  in [RFC 8032]. Breaking tradition, the keys are encoded in little-
    ///  endian byte order.
    /// ```
    pub fn from_public_bytes(public_key: &'k [u8]) -> ProtoResult<Self> {
        if public_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(format!(
                "expected {} byte public_key: {}",
                ED25519_PUBLIC_KEY_LEN,
                public_key.len()
            )
            .into());
        }

        Ok(Ed25519 { raw: public_key })
    }
}

#[cfg(feature = "dnssec-ring")]
impl<'k> PublicKey for Ed25519<'k> {
    // TODO: just store reference to public key bytes in ctor...
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    fn verify(&self, _: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, self.raw);
        public_key.verify(message, signature).map_err(Into::into)
    }
}

/// Rsa public key
#[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
pub struct Rsa<'k> {
    raw: &'k [u8],

    #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
    pkey: PKey<Public>,

    #[cfg(feature = "dnssec-ring")]
    pkey: RSAPublicKey<'k>,
}

#[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
impl<'k> Rsa<'k> {
    /// ```text
    /// RFC 3110              RSA SIGs and KEYs in the DNS              May 2001
    ///
    ///       2. RSA Public KEY Resource Records
    ///
    ///  RSA public keys are stored in the DNS as KEY RRs using algorithm
    ///  number 5 [RFC2535].  The structure of the algorithm specific portion
    ///  of the RDATA part of such RRs is as shown below.
    ///
    ///        Field             Size
    ///        -----             ----
    ///        exponent length   1 or 3 octets (see text)
    ///        exponent          as specified by length field
    ///        modulus           remaining space
    ///
    ///  For interoperability, the exponent and modulus are each limited to
    ///  4096 bits in length.  The public key exponent is a variable length
    ///  unsigned integer.  Its length in octets is represented as one octet
    ///  if it is in the range of 1 to 255 and by a zero octet followed by a
    ///  two octet unsigned length if it is longer than 255 bytes.  The public
    ///  key modulus field is a multiprecision unsigned integer.  The length
    ///  of the modulus can be determined from the RDLENGTH and the preceding
    ///  RDATA fields including the exponent.  Leading zero octets are
    ///  prohibited in the exponent and modulus.
    ///
    ///  Note: KEY RRs for use with RSA/SHA1 DNS signatures MUST use this
    ///  algorithm number (rather than the algorithm number specified in the
    ///  obsoleted RFC 2537).
    ///
    ///  Note: This changes the algorithm number for RSA KEY RRs to be the
    ///  same as the new algorithm number for RSA/SHA1 SIGs.
    /// ```
    pub fn from_public_bytes(raw: &'k [u8]) -> ProtoResult<Self> {
        let parsed = RSAPublicKey::try_from(raw)?;
        let pkey = into_pkey(parsed)?;
        Ok(Rsa { raw, pkey })
    }
}

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
fn into_pkey(parsed: RSAPublicKey<'_>) -> ProtoResult<PKey<Public>> {
    // FYI: BigNum slices treat all slices as BigEndian, i.e NetworkByteOrder
    let e = BigNum::from_slice(parsed.e())?;
    let n = BigNum::from_slice(parsed.n())?;

    OpenSslRsa::from_public_components(n, e)
        .and_then(PKey::from_rsa)
        .map_err(Into::into)
}

#[cfg(feature = "dnssec-ring")]
#[allow(clippy::unnecessary_wraps)]
fn into_pkey(parsed: RSAPublicKey<'_>) -> ProtoResult<RSAPublicKey<'_>> {
    Ok(parsed)
}

#[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
impl<'k> PublicKey for Rsa<'k> {
    fn public_bytes(&self) -> &[u8] {
        self.raw
    }

    #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        verify_with_pkey(&self.pkey, algorithm, message, signature)
    }

    #[cfg(feature = "dnssec-ring")]
    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        #[allow(deprecated)]
        let alg = match algorithm {
            Algorithm::RSASHA256 => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            Algorithm::RSASHA512 => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            Algorithm::RSASHA1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::RSASHA1NSEC3SHA1 => {
                return Err("*ring* doesn't support RSASHA1NSEC3SHA1 yet".into())
            }
            _ => unreachable!("non-RSA algorithm passed to RSA verify()"),
        };
        let public_key = signature::RsaPublicKeyComponents {
            n: self.pkey.n(),
            e: self.pkey.e(),
        };
        public_key
            .verify(alg, message, signature)
            .map_err(Into::into)
    }
}

/// Variants of all know public keys
#[non_exhaustive]
pub enum PublicKeyEnum<'k> {
    /// RSA keypair, supported by OpenSSL
    #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
    Rsa(Rsa<'k>),
    /// Elliptic curve keypair
    #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
    Ec(Ec<'k>),
    /// Elliptic curve keypair
    #[cfg(feature = "dnssec-ring")]
    Ec(Ec),
    /// Ed25519 public key for the Algorithm::ED25519
    #[cfg(feature = "dnssec-ring")]
    Ed25519(Ed25519<'k>),
    /// PhatomData for compiler when ring and or openssl not defined, do not use...
    #[cfg(not(any(feature = "dnssec-ring", feature = "dnssec-openssl")))]
    Phantom(&'k PhantomData<()>),
}

impl<'k> PublicKeyEnum<'k> {
    /// Converts the bytes into a PulbicKey of the specified algorithm
    #[allow(unused_variables, clippy::match_single_binding)]
    pub fn from_public_bytes(public_key: &'k [u8], algorithm: Algorithm) -> ProtoResult<Self> {
        // try to keep this and `Algorithm::is_supported` in sync
        debug_assert!(algorithm.is_supported());

        #[allow(deprecated)]
        match algorithm {
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => Ok(PublicKeyEnum::Ec(
                Ec::from_public_bytes(public_key, algorithm)?,
            )),
            #[cfg(feature = "dnssec-ring")]
            Algorithm::ED25519 => Ok(PublicKeyEnum::Ed25519(Ed25519::from_public_bytes(
                public_key,
            )?)),
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            Algorithm::RSASHA1
            | Algorithm::RSASHA1NSEC3SHA1
            | Algorithm::RSASHA256
            | Algorithm::RSASHA512 => Ok(PublicKeyEnum::Rsa(Rsa::from_public_bytes(public_key)?)),
            _ => Err("public key algorithm not supported".into()),
        }
    }
}

impl<'k> PublicKey for PublicKeyEnum<'k> {
    #[allow(clippy::match_single_binding, clippy::match_single_binding)]
    fn public_bytes(&self) -> &[u8] {
        match self {
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Ec(ec) => ec.public_bytes(),
            #[cfg(feature = "dnssec-ring")]
            PublicKeyEnum::Ed25519(ed) => ed.public_bytes(),
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Rsa(rsa) => rsa.public_bytes(),
            #[cfg(not(any(feature = "dnssec-ring", feature = "dnssec-openssl")))]
            _ => panic!("no public keys registered, enable ring or openssl features"),
        }
    }

    #[allow(unused_variables, clippy::match_single_binding)]
    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        match self {
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Ec(ec) => ec.verify(algorithm, message, signature),
            #[cfg(feature = "dnssec-ring")]
            PublicKeyEnum::Ed25519(ed) => ed.verify(algorithm, message, signature),
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Rsa(rsa) => rsa.verify(algorithm, message, signature),
            #[cfg(not(any(feature = "dnssec-ring", feature = "dnssec-openssl")))]
            _ => panic!("no public keys registered, enable ring or openssl features"),
        }
    }
}

/// An owned variant of PublicKey
pub struct PublicKeyBuf {
    key_buf: Vec<u8>,
}

impl PublicKeyBuf {
    /// Constructs a new PublicKey from the specified bytes, these should be in DNSKEY form.
    pub fn new(key_buf: Vec<u8>) -> Self {
        Self { key_buf }
    }

    /// Constructs a new [`PublicKeyBuf`] from an [`OpenSslRsa`] key.
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_rsa<T: HasPublic>(key: &OpenSslRsa<T>) -> Self {
        let mut key_buf = Vec::new();

        // this is to get us access to the exponent and the modulus
        let e = key.e().to_vec();
        let n = key.n().to_vec();

        if e.len() > 255 {
            key_buf.push(0);
            key_buf.push((e.len() >> 8) as u8);
        }

        key_buf.push(e.len() as u8);
        key_buf.extend_from_slice(&e);
        key_buf.extend_from_slice(&n);
        Self { key_buf }
    }

    /// Constructs a new [`PublicKeyBuf`] from an openssl [`EcKey`].
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_ec<T: HasPublic>(ec_key: &EcKey<T>) -> DnsSecResult<Self> {
        let group = ec_key.group();
        let point = ec_key.public_key();

        let mut key_buf = BigNumContext::new().and_then(|mut ctx| {
            point.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        })?;

        // Remove OpenSSL header byte
        key_buf.remove(0);
        Ok(Self { key_buf })
    }

    /// Extract the inner buffer of public key bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.key_buf
    }
}

impl PublicKey for PublicKeyBuf {
    fn public_bytes(&self) -> &[u8] {
        &self.key_buf
    }

    fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        let public_key = PublicKeyEnum::from_public_bytes(&self.key_buf, algorithm)?;

        public_key.verify(algorithm, message, signature)
    }
}

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
#[cfg(test)]
mod tests {
    #[cfg(feature = "dnssec-openssl")]
    #[test]
    fn test_asn1_emit_integer() {
        fn test_case(source: &[u8], expected_data: &[u8]) {
            use crate::rr::dnssec::public_key::asn1_emit_integer;

            let mut output = Vec::<u8>::new();
            asn1_emit_integer(&mut output, source);
            assert_eq!(output[0], 0x02);
            assert_eq!(output[1], expected_data.len() as u8);
            assert_eq!(&output[2..], expected_data);
        }
        test_case(&[0x00], &[0x00]);
        test_case(&[0x00, 0x00], &[0x00]);
        test_case(&[0x7f], &[0x7f]);
        test_case(&[0x80], &[0x00, 0x80]);
        test_case(&[0x00, 0x80], &[0x00, 0x80]);
        test_case(&[0x00, 0x00, 0x80], &[0x00, 0x80]);
        test_case(&[0x7f, 0x00, 0x80], &[0x7f, 0x00, 0x80]);
        test_case(&[0x00, 0x7f, 0x00, 0x80], &[0x7f, 0x00, 0x80]);
        test_case(&[0x80, 0x00, 0x80], &[0x00, 0x80, 0x00, 0x80]);
        test_case(&[0xff, 0x00, 0x80], &[0x00, 0xff, 0x00, 0x80]);
    }
}
