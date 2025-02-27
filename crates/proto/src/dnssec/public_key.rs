// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types

use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Algorithm, crypto::decode_public_key};
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

/// An owned variant of PublicKey
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
