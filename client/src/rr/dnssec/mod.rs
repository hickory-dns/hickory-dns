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

use trust_dns_proto::algorithm;
use trust_dns_proto::digest_type;
#[cfg(any(feature = "openssl", feature = "ring"))]
use trust_dns_proto::ec_public_key;
#[cfg(any(feature = "openssl", feature = "ring"))]
mod key_format;
mod keypair;
use trust_dns_proto::nsec3;
use mod trust_dns_proto::public_key;
#[cfg(any(feature = "openssl", feature = "ring"))]
use trust_dns_proto::rsa_public_key;
mod signer;
use trust_dns_proto::supported_algorithm;
use trust_dns_proto::tbs;
use trust_dns_proto::trust_anchor;
use trust_dns_proto::verifier;

pub use algorithm::Algorithm;
pub use digest_type::DigestType;
#[cfg(any(feature = "openssl", feature = "ring"))]
pub use self::key_format::KeyFormat;
pub use self::keypair::KeyPair;
pub use nsec3::Nsec3HashAlgorithm;
pub use public_key::PublicKey;
pub use public_key::PublicKeyBuf;
pub use public_key::PublicKeyEnum;
pub use self::signer::Signer;
pub use supported_algorithm::SupportedAlgorithms;
pub use trust_anchor::TrustAnchor;
pub use tbs::TBS;
pub use verifier::Verifier;

pub use error::DnsSecError;
pub use error::DnsSecErrorKind;
pub use error::DnsSecChainErr;
pub use error::DnsSecResult;

#[cfg(all(not(feature = "ring"), feature = "openssl"))]
pub use openssl::hash::DigestBytes as Digest;

#[cfg(feature = "ring")]
pub use ring::digest::Digest;
