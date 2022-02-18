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
#[cfg(feature = "openssl")]
use openssl::hash;

#[cfg(feature = "ring")]
use ring::digest;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::dnssec::Algorithm;

#[cfg(any(feature = "ring", feature = "openssl"))]
use super::Digest;

/// This is the digest format for the
///
///```text
/// 0 Reserved - [RFC3658]
/// 1 SHA-1 MANDATORY [RFC3658]
/// 2 SHA-256 MANDATORY [RFC4509]
/// 3 GOST R 34.11-94 OPTIONAL [RFC5933]
/// 4 SHA-384 OPTIONAL [RFC6605]
/// 5 ED25519 [RFC draft-ietf-curdle-dnskey-eddsa-03]
/// 5-255 Unassigned -
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum DigestType {
    /// [RFC 3658](https://tools.ietf.org/html/rfc3658)
    SHA1,
    /// [RFC 4509](https://tools.ietf.org/html/rfc4509)
    SHA256,
    /// [RFC 5933](https://tools.ietf.org/html/rfc5933)
    GOSTR34_11_94,
    /// [RFC 6605](https://tools.ietf.org/html/rfc6605)
    SHA384,
    /// Undefined
    SHA512,
    /// This is a passthrough digest as ED25519 is self-packaged
    ED25519,
}

impl DigestType {
    /// TODO: add an Unknown DigestType and make this infallible
    /// <http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
    pub fn from_u8(value: u8) -> ProtoResult<Self> {
        match value {
            1 => Ok(Self::SHA1),
            2 => Ok(Self::SHA256),
            3 => Ok(Self::GOSTR34_11_94),
            4 => Ok(Self::SHA384),
            5 => Ok(Self::ED25519),
            _ => Err(ProtoErrorKind::UnknownAlgorithmTypeValue(value).into()),
        }
    }

    /// The OpenSSL counterpart for the digest
    #[cfg(feature = "openssl")]
    #[cfg_attr(docsrs, doc(cfg(feature = "openssl")))]
    pub fn to_openssl_digest(self) -> ProtoResult<hash::MessageDigest> {
        match self {
            Self::SHA1 => Ok(hash::MessageDigest::sha1()),
            Self::SHA256 => Ok(hash::MessageDigest::sha256()),
            Self::SHA384 => Ok(hash::MessageDigest::sha384()),
            Self::SHA512 => Ok(hash::MessageDigest::sha512()),
            _ => Err(format!("digest not supported by openssl: {:?}", self).into()),
        }
    }

    /// The *ring* counterpart for the digest
    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn to_ring_digest_alg(self) -> ProtoResult<&'static digest::Algorithm> {
        match self {
            Self::SHA1 => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
            Self::SHA256 => Ok(&digest::SHA256),
            Self::SHA384 => Ok(&digest::SHA384),
            Self::SHA512 => Ok(&digest::SHA512),
            _ => Err(format!("digest not supported by ring: {:?}", self).into()),
        }
    }

    /// Hash the data
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
    pub fn hash(self, data: &[u8]) -> ProtoResult<Digest> {
        hash::hash(self.to_openssl_digest()?, data).map_err(Into::into)
    }

    /// Hash the data
    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn hash(self, data: &[u8]) -> ProtoResult<Digest> {
        let alg = self.to_ring_digest_alg()?;
        Ok(digest::digest(alg, data))
    }

    /// This will always error, enable openssl feature at compile time
    #[cfg(not(any(feature = "openssl", feature = "ring")))]
    #[cfg_attr(docsrs, doc(cfg(not(any(feature = "openssl", feature = "ring")))))]
    pub fn hash(self, _: &[u8]) -> ProtoResult<Vec<u8>> {
        Err("The openssl and ring features are both disabled".into())
    }

    /// Digest all the data.
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    #[cfg_attr(docsrs, doc(cfg(all(not(feature = "ring"), feature = "openssl"))))]
    pub fn digest_all(self, data: &[&[u8]]) -> ProtoResult<Digest> {
        use std::io::Write;

        let digest_type = self.to_openssl_digest()?;
        hash::Hasher::new(digest_type)
            .map_err(Into::into)
            .and_then(|mut hasher| {
                for d in data {
                    hasher.write_all(d)?;
                }
                hasher.finish().map_err(Into::into)
            })
    }

    /// Digest all the data.
    #[cfg(feature = "ring")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    pub fn digest_all(self, data: &[&[u8]]) -> ProtoResult<Digest> {
        let alg = self.to_ring_digest_alg()?;
        let mut ctx = digest::Context::new(alg);
        for d in data {
            ctx.update(d);
        }
        Ok(ctx.finish())
    }
}

impl From<Algorithm> for DigestType {
    fn from(a: Algorithm) -> Self {
        #[allow(deprecated)]
        match a {
            Algorithm::RSAMD5
            | Algorithm::DSA
            | Algorithm::RSASHA1
            | Algorithm::RSASHA1NSEC3SHA1 => Self::SHA1,
            Algorithm::RSASHA256 | Algorithm::ECDSAP256SHA256 => Self::SHA256,
            Algorithm::RSASHA512 => Self::SHA512,
            Algorithm::ECDSAP384SHA384 => Self::SHA384,
            Algorithm::ED25519 => Self::ED25519,
            Algorithm::Unknown(_) => Self::SHA512,
        }
    }
}

impl From<DigestType> for u8 {
    fn from(a: DigestType) -> Self {
        match a {
            DigestType::SHA1 => 1,
            DigestType::SHA256 => 2,
            DigestType::GOSTR34_11_94 => 3,
            DigestType::SHA384 => 4,
            DigestType::ED25519 => 5,
            DigestType::SHA512 => 255,
        }
    }
}
