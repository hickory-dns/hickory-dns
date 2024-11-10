// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(clippy::use_self)]

#[cfg(feature = "dnssec-openssl")]
use openssl::hash;

#[cfg(feature = "dnssec-ring")]
use ring::digest;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Algorithm, Digest};
use crate::error::{ProtoError, ProtoErrorKind, ProtoResult};

/// DNSSEC Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms
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
///
/// <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum DigestType {
    /// [RFC 3658](https://tools.ietf.org/html/rfc3658)
    SHA1,
    /// [RFC 4509](https://tools.ietf.org/html/rfc4509)
    SHA256,
    /// [RFC 6605](https://tools.ietf.org/html/rfc6605)
    SHA384,
    /// Formally undefined
    SHA512,
}

impl DigestType {
    /// TODO: add an Unknown DigestType and make this infallible
    /// <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
    pub fn from_u8(value: u8) -> ProtoResult<Self> {
        match value {
            1 => Ok(Self::SHA1),
            2 => Ok(Self::SHA256),
            4 => Ok(Self::SHA384),
            _ => Err(ProtoErrorKind::UnknownAlgorithmTypeValue(value).into()),
        }
    }

    /// The OpenSSL counterpart for the digest
    #[cfg(feature = "dnssec-openssl")]
    pub fn to_openssl_digest(self) -> hash::MessageDigest {
        match self {
            Self::SHA1 => hash::MessageDigest::sha1(),
            Self::SHA256 => hash::MessageDigest::sha256(),
            Self::SHA384 => hash::MessageDigest::sha384(),
            Self::SHA512 => hash::MessageDigest::sha512(),
        }
    }

    /// The *ring* counterpart for the digest
    #[cfg(feature = "dnssec-ring")]
    pub fn to_ring_digest_alg(self) -> &'static digest::Algorithm {
        match self {
            Self::SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::SHA256 => &digest::SHA256,
            Self::SHA384 => &digest::SHA384,
            Self::SHA512 => &digest::SHA512,
        }
    }

    /// Hash the data
    #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
    pub fn hash(self, data: &[u8]) -> ProtoResult<Digest> {
        hash::hash(self.to_openssl_digest(), data).map_err(Into::into)
    }

    /// Hash the data
    #[cfg(feature = "dnssec-ring")]
    pub fn hash(self, data: &[u8]) -> ProtoResult<Digest> {
        Ok(digest::digest(self.to_ring_digest_alg(), data))
    }

    /// This will always error, enable openssl feature at compile time
    #[cfg(not(any(feature = "dnssec-openssl", feature = "dnssec-ring")))]
    pub fn hash(self, _: &[u8]) -> ProtoResult<Vec<u8>> {
        Err("The openssl and ring features are both disabled".into())
    }

    /// Digest all the data.
    #[cfg(all(not(feature = "dnssec-ring"), feature = "dnssec-openssl"))]
    pub fn digest_all(self, data: &[&[u8]]) -> ProtoResult<Digest> {
        use std::io::Write;

        let digest_type = self.to_openssl_digest();
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
    #[cfg(feature = "dnssec-ring")]
    pub fn digest_all(self, data: &[&[u8]]) -> ProtoResult<Digest> {
        let alg = self.to_ring_digest_alg();
        let mut ctx = digest::Context::new(alg);
        for d in data {
            ctx.update(d);
        }
        Ok(ctx.finish())
    }
}

impl TryFrom<Algorithm> for DigestType {
    type Error = ProtoError;

    fn try_from(a: Algorithm) -> Result<Self, Self::Error> {
        Ok(match a {
            #[allow(deprecated)]
            Algorithm::RSAMD5
            | Algorithm::DSA
            | Algorithm::RSASHA1
            | Algorithm::RSASHA1NSEC3SHA1 => Self::SHA1,
            Algorithm::RSASHA256 | Algorithm::ECDSAP256SHA256 => Self::SHA256,
            Algorithm::RSASHA512 => Self::SHA512,
            Algorithm::ECDSAP384SHA384 => Self::SHA384,
            _ => return Err(format!("unsupported DigestType for algorithm {a:?}").into()),
        })
    }
}

impl From<DigestType> for u8 {
    fn from(a: DigestType) -> Self {
        match a {
            DigestType::SHA1 => 1,
            DigestType::SHA256 => 2,
            DigestType::SHA384 => 4,
            DigestType::SHA512 => 255,
        }
    }
}
