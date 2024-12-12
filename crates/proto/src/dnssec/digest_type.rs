// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::Algorithm;
use crate::error::{ProtoError, ProtoErrorKind};

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

impl TryFrom<u8> for DigestType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SHA1),
            2 => Ok(Self::SHA256),
            4 => Ok(Self::SHA384),
            _ => Err(ProtoErrorKind::UnknownAlgorithmTypeValue(value).into()),
        }
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
