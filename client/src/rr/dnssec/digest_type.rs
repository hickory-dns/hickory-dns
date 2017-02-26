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
#[cfg(feature = "openssl")]
use openssl::hash::MessageDigest;

use rr::dnssec::Algorithm;
use ::error::*;

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
    SHA1, // [RFC3658]
    SHA256, // [RFC4509]
    // GOSTR34_11_94, // [RFC5933]
    SHA384, // [RFC6605]
    SHA512,
    ED25519, // this is a passthrough digest as ED25519 is self-packaged
}

impl DigestType {
    /// http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    pub fn from_u8(value: u8) -> DecodeResult<Self> {
        match value {
            1 => Ok(DigestType::SHA1),
            2 => Ok(DigestType::SHA256),
            //  3  => Ok(DigestType::GOSTR34_11_94),
            4 => Ok(DigestType::SHA384),
            5 => Ok(DigestType::ED25519),
            _ => Err(DecodeErrorKind::UnknownAlgorithmTypeValue(value).into()),
        }
    }

    #[cfg(feature = "openssl")]
    pub fn to_openssl_digest(&self) -> DnsSecResult<MessageDigest> {
        match *self {
            DigestType::SHA1 => Ok(MessageDigest::sha1()),
            DigestType::SHA256 => Ok(MessageDigest::sha256()),
            DigestType::SHA384 => Ok(MessageDigest::sha384()),
            DigestType::SHA512 => Ok(MessageDigest::sha512()),
            _ => {
                Err(DnsSecErrorKind::Msg(format!("digest not supported by openssl: {:?}", self))
                    .into())
            }
        }
    }

    #[cfg(feature = "openssl")]
    pub fn hash(&self, data: &[u8]) -> DnsSecResult<Vec<u8>> {
        hash::hash(try!(self.to_openssl_digest()), data).map_err(|e| e.into())
    }

    #[cfg(not(feature = "openssl"))]
    pub fn hash(&self, _: &[u8]) -> DnsSecResult<Vec<u8>> {
        Err(DnsSecErrorKind::Message("openssl feature not enabled").into())
    }
}

impl From<Algorithm> for DigestType {
    fn from(a: Algorithm) -> DigestType {
        match a {
            Algorithm::RSASHA1 |
            Algorithm::RSASHA1NSEC3SHA1 => DigestType::SHA1,
            Algorithm::RSASHA256 => DigestType::SHA256,
            Algorithm::RSASHA512 => DigestType::SHA512,
            Algorithm::ECDSAP256SHA256 => DigestType::SHA256,
            Algorithm::ECDSAP384SHA384 => DigestType::SHA384,
            Algorithm::ED25519 => DigestType::ED25519,
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
