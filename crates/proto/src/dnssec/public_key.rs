// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Public Key implementations for supported key types
#[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
use std::marker::PhantomData;
use std::sync::Arc;

#[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
use super::openssl::{Ec, Rsa};
#[cfg(feature = "dnssec-ring")]
use super::ring::{Ec, Ed25519, Rsa};
use super::Algorithm;
use crate::error::ProtoResult;

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
        #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => Ok(Arc::new(
            Ec::from_public_bytes(public_key.to_vec(), algorithm)?,
        )),
        #[cfg(feature = "dnssec-ring")]
        Algorithm::ED25519 => Ok(Arc::new(Ed25519::from_public_bytes(public_key)?)),
        #[cfg(any(feature = "dnssec-openssl", feature = "dnssec-ring"))]
        Algorithm::RSASHA1
        | Algorithm::RSASHA1NSEC3SHA1
        | Algorithm::RSASHA256
        | Algorithm::RSASHA512 => Ok(Arc::new(Rsa::from_public_bytes(public_key.to_vec())?)),
        _ => Err("public key algorithm not supported".into()),
    }
}
