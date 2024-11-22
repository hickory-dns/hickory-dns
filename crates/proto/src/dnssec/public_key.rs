// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types
use std::sync::Arc;

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use super::openssl;
#[cfg(feature = "dnssec-ring")]
use super::ring;
use super::Algorithm;
use crate::error::ProtoResult;

#[derive(Clone)]
pub(super) enum MaybePublicKey {
    Valid(Arc<dyn PublicKey>),
    Invalid(Vec<u8>),
}

impl MaybePublicKey {
    pub(crate) fn from_slice(public_key: &[u8], algorithm: Algorithm) -> ProtoResult<Self> {
        match decode_public_key(public_key, algorithm) {
            Ok(pk) => Ok(MaybePublicKey::Valid(pk)),
            Err(_) => Ok(MaybePublicKey::Invalid(public_key.to_vec())),
        }
    }
}

impl AsRef<[u8]> for MaybePublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            MaybePublicKey::Valid(pk) => pk.public_bytes(),
            MaybePublicKey::Invalid(pk) => pk,
        }
    }
}

/// PublicKeys implement the ability to ideally be zero copy abstractions over public keys for verifying signed content.
///
/// In DNS the KEY and DNSKEY types are generally the RData types which store public key material.
pub trait PublicKey: Send + Sync + 'static {
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

/// Decode a public key according to the specified `Algorithm`.
///
/// Availability of algorithms and public key formats depends on the configured
/// backends (`dnssec-ring` and/or `dnssec-openssl`).
pub fn decode_public_key(
    public_key: &[u8],
    algorithm: Algorithm,
) -> ProtoResult<Arc<dyn PublicKey>> {
    #[allow(deprecated)]
    match algorithm {
        #[cfg(feature = "dnssec-ring")]
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => Ok(Arc::new(
            ring::Ec::from_public_bytes(public_key.to_vec(), algorithm)?,
        )),
        #[cfg(feature = "dnssec-ring")]
        Algorithm::ED25519 => Ok(Arc::new(ring::Ed25519::from_public_bytes(public_key)?)),
        #[cfg(feature = "dnssec-ring")]
        Algorithm::RSASHA1
        | Algorithm::RSASHA1NSEC3SHA1
        | Algorithm::RSASHA256
        | Algorithm::RSASHA512 => Ok(Arc::new(ring::Rsa::from_public_bytes(public_key.to_vec())?)),
        #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => Ok(Arc::new(
            openssl::Ec::from_public_bytes(public_key.to_vec(), algorithm)?,
        )),
        #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
        Algorithm::RSASHA1
        | Algorithm::RSASHA1NSEC3SHA1
        | Algorithm::RSASHA256
        | Algorithm::RSASHA512 => Ok(Arc::new(openssl::Rsa::from_public_bytes(
            public_key.to_vec(),
        )?)),
        _ => Err("public key algorithm not supported".into()),
    }
}
