// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! dns security extension related modules

mod algorithm;
mod digest_type;
#[cfg(any(feature = "openssl", feature = "ring"))]
mod ec_public_key;
mod key_format;
mod keypair;
mod nsec3;
pub mod proof;
pub mod public_key;
pub mod rdata;
#[cfg(any(feature = "openssl", feature = "ring"))]
mod rsa_public_key;
mod signer;
mod supported_algorithm;
pub mod tbs;
mod trust_anchor;
pub mod tsig;
mod verifier;

pub use self::algorithm::Algorithm;
pub use self::digest_type::DigestType;
pub use self::nsec3::Nsec3HashAlgorithm;
pub use self::proof::Proof;
pub use self::public_key::PublicKey;
pub use self::public_key::PublicKeyBuf;
pub use self::public_key::PublicKeyEnum;
pub use self::supported_algorithm::SupportedAlgorithms;
pub use self::tbs::TBS;
pub use self::trust_anchor::TrustAnchor;
pub use self::verifier::Verifier;
pub use crate::error::DnsSecResult;

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
pub use openssl::hash::DigestBytes as Digest;

#[cfg(feature = "ring")]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
pub use ring::digest::Digest;

/// This is an empty type, enable Ring or OpenSSL for this feature
#[cfg(not(any(feature = "openssl", feature = "ring")))]
#[cfg_attr(docsrs, doc(cfg(not(any(feature = "openssl", feature = "ring")))))]
#[derive(Clone, Copy, Debug)]
pub struct Digest;

#[cfg(not(any(feature = "openssl", feature = "ring")))]
#[cfg_attr(docsrs, doc(cfg(not(any(feature = "openssl", feature = "ring")))))]
#[allow(clippy::should_implement_trait)]
impl Digest {
    /// This is an empty type, enable Ring or OpenSSL for this feature
    pub fn as_ref(&self) -> &Self {
        self
    }

    /// This is an empty type, enable Ring or OpenSSL for this feature
    #[allow(clippy::wrong_self_convention)]
    pub fn to_owned(&self) -> Vec<u8> {
        vec![]
    }
}

#[cfg(any(feature = "openssl", feature = "ring"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "openssl", feature = "ring"))))]
pub use self::key_format::KeyFormat;
pub use self::keypair::KeyPair;
#[allow(deprecated)]
pub use self::signer::{SigSigner, Signer};

#[cfg(feature = "openssl")]
#[cfg_attr(docsrs, doc(cfg(feature = "openssl")))]
pub use openssl::pkey::{HasPrivate, HasPublic, Private, Public};

#[cfg(not(feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "openssl"))))]
pub use self::faux_key_type::{HasPrivate, HasPublic, Private, Public};

#[cfg(not(feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "openssl"))))]
mod faux_key_type {
    /// A key that contains public key material
    pub trait HasPublic {}

    /// A key that contains private key material
    pub trait HasPrivate {}

    impl<K: HasPrivate> HasPublic for K {}

    /// Faux implementation of the Openssl Public key types
    #[derive(Clone, Copy)]
    pub enum Public {}

    impl HasPublic for Public {}

    /// Faux implementation of the Openssl Public key types
    #[derive(Clone, Copy)]
    pub enum Private {}

    impl HasPrivate for Private {}
}
