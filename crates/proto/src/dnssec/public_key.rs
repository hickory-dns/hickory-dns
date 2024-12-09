// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types

use std::sync::Arc;

#[cfg(feature = "dnssec-ring")]
use super::ring;
use super::Algorithm;
use crate::error::ProtoResult;

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

pub(super) fn decode_public_key<'a>(
    public_key: &'a [u8],
    algorithm: Algorithm,
) -> ProtoResult<Arc<dyn PublicKey + 'a>> {
    // try to keep this and `Algorithm::is_supported` in sync
    debug_assert!(algorithm.is_supported());

    #[allow(deprecated)]
    match algorithm {
        #[cfg(feature = "dnssec-ring")]
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => Ok(Arc::new(
            ring::Ec::from_public_bytes(public_key, algorithm)?,
        )),
        #[cfg(feature = "dnssec-ring")]
        Algorithm::ED25519 => Ok(Arc::new(ring::Ed25519::from_public_bytes(
            public_key.into(),
        )?)),
        #[cfg(feature = "dnssec-ring")]
        Algorithm::RSASHA1
        | Algorithm::RSASHA1NSEC3SHA1
        | Algorithm::RSASHA256
        | Algorithm::RSASHA512 => Ok(Arc::new(ring::Rsa::from_public_bytes(
            public_key, algorithm,
        )?)),
        _ => Err("public key algorithm not supported".into()),
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
        decode_public_key(&self.key_buf, self.algorithm)?.verify(message, signature)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}
