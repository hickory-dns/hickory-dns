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
use openssl::nid::Nid;
#[cfg(feature = "dnssec-openssl")]
use openssl::pkey::HasPublic;
#[cfg(feature = "dnssec-openssl")]
use openssl::rsa::Rsa as OpenSslRsa;

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use super::openssl::{Ec, Rsa};
#[cfg(feature = "dnssec-ring")]
use super::ring::{Ec, Ed25519, Rsa};
use super::Algorithm;
use crate::error::{DnsSecResult, ProtoResult};

/// PublicKeys implement the ability to ideally be zero copy abstractions over public keys for verifying signed content.
///
/// In DNS the KEY and DNSKEY types are generally the RData types which store public key material.
pub trait PublicKey {
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
    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()>;

    /// The algorithm associated with this key.
    fn algorithm(&self) -> Algorithm;
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
            | Algorithm::RSASHA512 => Ok(PublicKeyEnum::Rsa(Rsa::from_public_bytes(
                public_key, algorithm,
            )?)),
            _ => Err("public key algorithm not supported".into()),
        }
    }
}

impl PublicKey for PublicKeyEnum<'_> {
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
    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        match self {
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Ec(ec) => ec.verify(message, signature),
            #[cfg(feature = "dnssec-ring")]
            PublicKeyEnum::Ed25519(ed) => ed.verify(message, signature),
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Rsa(rsa) => rsa.verify(message, signature),
            #[cfg(not(any(feature = "dnssec-ring", feature = "dnssec-openssl")))]
            _ => panic!("no public keys registered, enable ring or openssl features"),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Ec(ec) => ec.algorithm(),
            #[cfg(feature = "dnssec-ring")]
            PublicKeyEnum::Ed25519(ed) => ed.algorithm(),
            #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
            PublicKeyEnum::Rsa(rsa) => rsa.algorithm(),
            #[cfg(not(any(feature = "dnssec-ring", feature = "dnssec-openssl")))]
            _ => panic!("no public keys registered, enable ring or openssl features"),
        }
    }
}

/// An owned variant of PublicKey
pub struct PublicKeyBuf {
    key_buf: Vec<u8>,
    algorithm: Algorithm,
}

impl PublicKeyBuf {
    /// Constructs a new PublicKey from the specified bytes, these should be in DNSKEY form.
    pub fn new(key_buf: Vec<u8>, algorithm: Algorithm) -> Self {
        Self { key_buf, algorithm }
    }

    /// Constructs a new [`PublicKeyBuf`] from an [`OpenSslRsa`] key.
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_rsa<T: HasPublic>(key: &OpenSslRsa<T>, algorithm: Algorithm) -> Self {
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
        Self { key_buf, algorithm }
    }

    /// Constructs a new [`PublicKeyBuf`] from an openssl [`EcKey`].
    #[cfg(feature = "dnssec-openssl")]
    pub fn from_ec<T: HasPublic>(ec_key: &EcKey<T>) -> DnsSecResult<Self> {
        let group = ec_key.group();
        let algorithm = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Algorithm::ECDSAP256SHA256,
            Some(Nid::SECP384R1) => Algorithm::ECDSAP384SHA384,
            val => {
                return Err(format!(
                    "unsupported curve {val:?} ({:?})",
                    val.and_then(|nid| nid.long_name().ok())
                )
                .into())
            }
        };

        let point = ec_key.public_key();
        let mut key_buf = BigNumContext::new().and_then(|mut ctx| {
            point.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        })?;

        // Remove OpenSSL header byte
        key_buf.remove(0);
        Ok(Self { key_buf, algorithm })
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

    fn verify(&self, message: &[u8], signature: &[u8]) -> ProtoResult<()> {
        let public_key = PublicKeyEnum::from_public_bytes(&self.key_buf, self.algorithm)?;

        public_key.verify(message, signature)
    }

    fn algorithm(&self) -> Algorithm {
        let public_key = PublicKeyEnum::from_public_bytes(&self.key_buf, Algorithm::RSASHA256)
            .expect("algorithm should be supported");
        public_key.algorithm()
    }
}
