/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! dns security extension related modules

#[cfg(any(feature = "openssl", feature = "ring"))]
mod key_format;
mod keypair;
mod signer;
pub mod tsig;

use crate::proto::rr::dnssec;

pub use self::dnssec::tbs;
pub use self::dnssec::Algorithm;
pub use self::dnssec::DigestType;
pub use self::dnssec::Nsec3HashAlgorithm;
pub use self::dnssec::PublicKey;
pub use self::dnssec::PublicKeyBuf;
pub use self::dnssec::PublicKeyEnum;
pub use self::dnssec::SupportedAlgorithms;
pub use self::dnssec::TrustAnchor;
pub use self::dnssec::Verifier;
pub use self::dnssec::TBS;
#[cfg(any(feature = "openssl", feature = "ring"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "openssl", feature = "ring"))))]
pub use self::key_format::KeyFormat;
pub use self::keypair::KeyPair;
#[allow(deprecated)]
pub use self::signer::{SigSigner, Signer};

pub use crate::error::DnsSecError;
pub use crate::error::DnsSecErrorKind;
pub use crate::error::DnsSecResult;

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
pub use openssl::hash::DigestBytes as Digest;

#[cfg(feature = "ring")]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
pub use ring::digest::Digest;

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
