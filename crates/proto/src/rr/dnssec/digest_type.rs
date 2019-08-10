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

use crate::error::*;
use crate::rr::dnssec::Algorithm;

#[cfg(any(feature = "ring", feature = "openssl"))]
use super::Digest;

/// This is the digest format for the
///
///```text
/// 0	Reserved	-	[RFC3658]
/// 1	SHA-1	MANDATORY	[RFC3658]
/// 2	SHA-256	MANDATORY	[RFC4509]
/// 3	GOST R 34.11-94	OPTIONAL	[RFC5933]
/// 4	SHA-384	OPTIONAL	[RFC6605]
/// 5 ED25519 [RFC draft-ietf-curdle-dnskey-eddsa-03]
/// 5-255	Unassigned	-
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum DigestType {
    /// [RFC3658]
    SHA1,
    /// [RFC4509]
    SHA256, // [RFC4509]
    // GOSTR34_11_94, // [RFC5933]
    /// [RFC6605]
    SHA384,
    /// Undefined
    SHA512,
    /// This is a passthrough digest as ED25519 is self-packaged
    ED25519,
}

impl DigestType {
    /// TODO: add an Unknown DigestType and make this infallible
    /// http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    pub fn from_u8(value: u8) -> ProtoResult<Self> {
        match value {
            1 => Ok(DigestType::SHA1),
            2 => Ok(DigestType::SHA256),
            //  3  => Ok(DigestType::GOSTR34_11_94),
            4 => Ok(DigestType::SHA384),
            5 => Ok(DigestType::ED25519),
            _ => Err(ProtoErrorKind::UnknownAlgorithmTypeValue(value).into()),
        }
    }

    /// The OpenSSL counterpart for the digest
    #[cfg(feature = "openssl")]
    pub fn to_openssl_digest(self) -> ProtoResult<hash::MessageDigest> {
        match self {
            DigestType::SHA1 => Ok(hash::MessageDigest::sha1()),
            DigestType::SHA256 => Ok(hash::MessageDigest::sha256()),
            DigestType::SHA384 => Ok(hash::MessageDigest::sha384()),
            DigestType::SHA512 => Ok(hash::MessageDigest::sha512()),
            _ => Err(format!("digest not supported by openssl: {:?}", self).into()),
        }
    }

    /// The *ring* counterpart for the digest
    #[cfg(feature = "ring")]
    pub fn to_ring_digest_alg(self) -> ProtoResult<&'static digest::Algorithm> {
        match self {
            DigestType::SHA1 => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
            DigestType::SHA256 => Ok(&digest::SHA256),
            DigestType::SHA384 => Ok(&digest::SHA384),
            DigestType::SHA512 => Ok(&digest::SHA512),
            _ => Err(format!("digest not supported by ring: {:?}", self).into()),
        }
    }

    /// Hash the data
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
    pub fn hash(self, data: &[u8]) -> ProtoResult<Digest> {
        hash::hash(self.to_openssl_digest()?, data).map_err(Into::into)
    }

    /// Hash the data
    #[cfg(feature = "ring")]
    pub fn hash(self, data: &[u8]) -> ProtoResult<Digest> {
        let alg = self.to_ring_digest_alg()?;
        Ok(digest::digest(alg, data))
    }

    /// This will always error, enable openssl feature at compile time
    #[cfg(not(any(feature = "openssl", feature = "ring")))]
    pub fn hash(self, _: &[u8]) -> ProtoResult<Vec<u8>> {
        Err("The openssl and ring features are both disabled".into())
    }

    /// Digest all the data.
    #[cfg(all(not(feature = "ring"), feature = "openssl"))]
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
    fn from(a: Algorithm) -> DigestType {
        match a {
            Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => DigestType::SHA1,
            Algorithm::RSASHA256 | Algorithm::ECDSAP256SHA256 => DigestType::SHA256,
            Algorithm::RSASHA512 => DigestType::SHA512,
            Algorithm::ECDSAP384SHA384 => DigestType::SHA384,
            Algorithm::ED25519 => DigestType::ED25519,

            Algorithm::Unknown(_) => DigestType::SHA512,
        }
    }
}

impl From<DigestType> for u8 {
    fn from(a: DigestType) -> u8 {
        match a {
            DigestType::SHA1 => 1,
            DigestType::SHA256 => 2,
            // DigestType::GOSTR34_11_94 => 3,
            DigestType::SHA384 => 4,
            DigestType::ED25519 => 5,
            DigestType::SHA512 => 255,
        }
    }
}
