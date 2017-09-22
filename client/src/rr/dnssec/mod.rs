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

mod algorithm;
mod digest_type;
#[cfg(feature = "openssl")]
mod ec_public_key;
pub mod hash;
#[cfg(any(feature = "openssl", feature = "ring"))]
mod key_format;
mod keypair;
mod nsec3;
pub mod public_key;
mod signer;
mod supported_algorithm;
mod trust_anchor;
mod verifier;

pub use self::algorithm::Algorithm;
pub use self::digest_type::DigestType;
#[cfg(any(feature = "openssl", feature = "ring"))]
pub use self::key_format::KeyFormat;
pub use self::keypair::KeyPair;
pub use self::nsec3::Nsec3HashAlgorithm;
pub use self::public_key::PublicKey;
pub use self::public_key::PublicKeyEnum;
pub use self::signer::Signer;
pub use self::supported_algorithm::SupportedAlgorithms;
pub use self::trust_anchor::TrustAnchor;
pub use self::verifier::Verifier;

pub use error::DnsSecError;
pub use error::DnsSecErrorKind;
pub use error::DnsSecChainErr;
pub use error::DnsSecResult;

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
pub use openssl::hash::DigestBytes as Digest;

#[cfg(feature = "ring")]
pub use ring::digest::Digest;
