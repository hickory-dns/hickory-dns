// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types
#[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
use std::marker::PhantomData;

#[cfg(feature = "dnssec-openssl")]
use openssl::bn::BigNumContext;
#[cfg(feature = "dnssec-openssl")]
use openssl::ec::{EcKey, PointConversionForm};
#[cfg(feature = "dnssec-openssl")]
use openssl::pkey::HasPublic;
#[cfg(feature = "dnssec-openssl")]
use openssl::rsa::Rsa as OpenSslRsa;

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use super::openssl::{Ec, Rsa};
#[allow(deprecated)]
use super::rdata::key::{KeyTrust, KeyUsage, Protocol, UpdateScope};
use super::rdata::{DNSKEY, DS, KEY};
#[cfg(feature = "dnssec-ring")]
use super::ring::{Ec, Ed25519, Rsa};
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

/// Variants of all know public keys
#[non_exhaustive]
pub enum PublicKeyEnum<'k> {
    /// RSA keypair, supported by OpenSSL
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
