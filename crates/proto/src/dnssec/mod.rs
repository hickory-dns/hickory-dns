// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! dns security extension related modules

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::{ProtoError, ProtoErrorKind};

mod algorithm;
#[cfg(feature = "dnssec-ring")]
mod ec_public_key;
mod nsec3;
pub mod proof;
pub mod public_key;
pub mod rdata;
/// ring implementations of DNSSEC traits.
#[cfg(feature = "dnssec-ring")]
pub mod ring;
#[cfg(feature = "dnssec-ring")]
mod rsa_public_key;
mod signer;
mod supported_algorithm;
pub mod tbs;
mod trust_anchor;
pub mod tsig;
mod verifier;

pub use self::algorithm::Algorithm;
pub use self::nsec3::Nsec3HashAlgorithm;
pub use self::proof::{Proof, ProofError, ProofErrorKind, ProofFlags, Proven};
pub use self::public_key::{PublicKey, PublicKeyBuf};
pub use self::signer::SigSigner;
pub use self::supported_algorithm::SupportedAlgorithms;
pub use self::tbs::TBS;
pub use self::trust_anchor::TrustAnchor;
pub use self::verifier::Verifier;
pub use crate::error::DnsSecResult;

/// Decode private key
pub fn decode_key(
    bytes: &[u8],
    algorithm: Algorithm,
    format: KeyFormat,
) -> DnsSecResult<Box<dyn SigningKey>> {
    //  empty string prevents openssl from triggering a read from stdin...

    #[allow(deprecated)]
    match algorithm {
        Algorithm::Unknown(v) => Err(format!("unknown algorithm: {v}").into()),
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => match format {
            #[cfg(feature = "dnssec-ring")]
            KeyFormat::Pkcs8 => Ok(Box::new(ring::RsaSigningKey::from_pkcs8(bytes, algorithm)?)),
            e => Err(format!("unsupported key format with RSA: {e:?}").into()),
        },
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => match format {
            #[cfg(feature = "dnssec-ring")]
            KeyFormat::Pkcs8 => Ok(Box::new(ring::EcdsaSigningKey::from_pkcs8(
                bytes, algorithm,
            )?)),
            e => Err(format!("unsupported key format with EC: {e:?}").into()),
        },
        Algorithm::ED25519 => match format {
            #[cfg(feature = "dnssec-ring")]
            KeyFormat::Pkcs8 => Ok(Box::new(ring::Ed25519SigningKey::from_pkcs8(bytes)?)),
            e => Err(
                format!("unsupported key format with ED25519 (only Pkcs8 supported): {e:?}").into(),
            ),
        },
        e => Err(format!("unsupported Algorithm, enable openssl or ring feature: {e:?}").into()),
    }
}

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

/// A key that can be used to sign records.
pub trait SigningKey: Send + Sync + 'static {
    /// Sign DNS records.
    ///
    /// # Return value
    ///
    /// The signature, ready to be stored in an `RData::RRSIG`.
    fn sign(&self, tbs: &TBS) -> DnsSecResult<Vec<u8>>;

    /// Returns a [`PublicKeyBuf`] for this [`SigningKey`].
    fn to_public_key(&self) -> DnsSecResult<PublicKeyBuf>;
}

/// The format of the binary key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFormat {
    /// A der encoded key
    Der,
    /// A pem encoded key, the default of OpenSSL
    Pem,
    /// Pkcs8, a pkcs8 formatted private key
    Pkcs8,
}

#[cfg(test)]
mod test_utils {
    use rdata::DNSKEY;

    use super::*;

    pub(super) fn public_key_test(key: &dyn SigningKey, algorithm: Algorithm) {
        let pk = key.to_public_key().unwrap();

        let tbs = TBS::from(&b"www.example.com"[..]);
        let mut sig = key.sign(&tbs).unwrap();
        assert!(
            pk.verify(tbs.as_ref(), &sig).is_ok(),
            "public_key_test() failed to verify (algorithm: {algorithm:?})",
        );
        sig[10] = !sig[10];
        assert!(
            pk.verify(tbs.as_ref(), &sig).is_err(),
            "algorithm: {algorithm:?} (public key, neg)",
        );
    }

    pub(super) fn hash_test(key: &dyn SigningKey, neg: &dyn SigningKey, algorithm: Algorithm) {
        let tbs = TBS::from(&b"www.example.com"[..]);

        // TODO: convert to stored keys...
        let pub_key = key.to_public_key().unwrap();
        let neg_pub_key = neg.to_public_key().unwrap();

        let sig = key.sign(&tbs).unwrap();
        assert!(
            pub_key.verify(tbs.as_ref(), &sig).is_ok(),
            "algorithm: {algorithm:?}",
        );

        let pub_key = key.to_public_key().unwrap();
        let dns_key = DNSKEY::from_key(&pub_key);
        assert!(
            dns_key.verify(tbs.as_ref(), &sig).is_ok(),
            "algorithm: {algorithm:?} (dnskey)",
        );
        assert!(
            neg_pub_key.verify(tbs.as_ref(), &sig).is_err(),
            "algorithm: {:?} (neg)",
            algorithm
        );

        let neg_pub_key = neg.to_public_key().unwrap();
        let neg_dns_key = DNSKEY::from_key(&neg_pub_key);
        assert!(
            neg_dns_key.verify(tbs.as_ref(), &sig).is_err(),
            "algorithm: {algorithm:?} (dnskey, neg)",
        );
    }
}
