// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! dns security extension related modules

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use ::ring::error::{KeyRejected, Unspecified};
#[cfg(feature = "backtrace")]
use backtrace::Backtrace;
use rdata::tsig::TsigAlgorithm;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{ProtoError, ProtoErrorKind};
#[cfg(feature = "backtrace")]
use crate::trace;

mod algorithm;
mod dnssec_dns_handle;
#[doc(hidden)]
pub use dnssec_dns_handle::verify_nsec;
pub use dnssec_dns_handle::DnssecDnsHandle;
/// Cryptographic backend implementations of DNSSEC traits.
pub mod crypto;
mod ec_public_key;
mod nsec3;
pub mod proof;
pub mod public_key;
pub mod rdata;
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

    /// Returns the algorithm of the key.
    fn algorithm(&self) -> Algorithm;
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

/// An alias for dnssec results returned by functions of this crate
pub type DnsSecResult<T> = ::std::result::Result<T, DnsSecError>;

/// The error type for dnssec errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct DnsSecError {
    kind: DnsSecErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<Backtrace>,
}

impl DnsSecError {
    /// Get the kind of the error
    pub fn kind(&self) -> &DnsSecErrorKind {
        &self.kind
    }
}

impl fmt::Display for DnsSecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(backtrace) = &self.backtrack {
                    fmt::Display::fmt(&self.kind, f)?;
                    fmt::Debug::fmt(backtrace, f)
                } else {
                    fmt::Display::fmt(&self.kind, f)
                }
            } else {
                fmt::Display::fmt(&self.kind, f)
            }
        }
    }
}

impl From<DnsSecErrorKind> for DnsSecError {
    fn from(kind: DnsSecErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for DnsSecError {
    fn from(msg: &'static str) -> Self {
        DnsSecErrorKind::Message(msg).into()
    }
}

impl From<String> for DnsSecError {
    fn from(msg: String) -> Self {
        DnsSecErrorKind::Msg(msg).into()
    }
}

impl From<ProtoError> for DnsSecError {
    fn from(e: ProtoError) -> Self {
        match e.kind() {
            ProtoErrorKind::Timeout => DnsSecErrorKind::Timeout.into(),
            _ => DnsSecErrorKind::from(e).into(),
        }
    }
}

impl From<KeyRejected> for DnsSecError {
    fn from(e: KeyRejected) -> Self {
        DnsSecErrorKind::from(e).into()
    }
}

impl From<Unspecified> for DnsSecError {
    fn from(e: Unspecified) -> Self {
        DnsSecErrorKind::from(e).into()
    }
}

/// The error kind for dnssec errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsSecErrorKind {
    /// An HMAC failed to verify
    #[error("hmac validation failure")]
    HmacInvalid,

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    // foreign
    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// A ring error
    #[error("ring error: {0}")]
    RingKeyRejected(#[from] KeyRejected),

    /// A ring error
    #[error("ring error: {0}")]
    RingUnspecified(#[from] Unspecified),

    /// A request timed out
    #[error("request timed out")]
    Timeout,

    /// Tsig unsupported mac algorithm
    /// Supported algorithm documented in `TsigAlgorithm::supported` function.
    #[error("Tsig unsupported mac algorithm")]
    TsigUnsupportedMacAlgorithm(TsigAlgorithm),

    /// Tsig key verification failed
    #[error("Tsig key wrong key error")]
    TsigWrongKey,
}

impl Clone for DnsSecErrorKind {
    fn clone(&self) -> Self {
        use DnsSecErrorKind::*;
        match self {
            HmacInvalid => HmacInvalid,
            Message(msg) => Message(msg),
            Msg(msg) => Msg(msg.clone()),
            // foreign
            Proto(proto) => Proto(proto.clone()),
            RingKeyRejected(r) => Msg(format!("Ring rejected key: {r}")),
            RingUnspecified(_r) => RingUnspecified(Unspecified),
            Timeout => Timeout,
            TsigUnsupportedMacAlgorithm(ref alg) => TsigUnsupportedMacAlgorithm(alg.clone()),
            TsigWrongKey => TsigWrongKey,
        }
    }
}

#[cfg(test)]
mod test_utils {
    use rdata::DNSKEY;

    use super::*;

    pub(super) fn public_key_test(key: &dyn SigningKey) {
        let pk = key.to_public_key().unwrap();

        let tbs = TBS::from(&b"www.example.com"[..]);
        let mut sig = key.sign(&tbs).unwrap();
        assert!(
            pk.verify(tbs.as_ref(), &sig).is_ok(),
            "public_key_test() failed to verify (algorithm: {:?})",
            key.algorithm(),
        );
        sig[10] = !sig[10];
        assert!(
            pk.verify(tbs.as_ref(), &sig).is_err(),
            "algorithm: {:?} (public key, neg)",
            key.algorithm(),
        );
    }

    pub(super) fn hash_test(key: &dyn SigningKey, neg: &dyn SigningKey) {
        let tbs = TBS::from(&b"www.example.com"[..]);

        // TODO: convert to stored keys...
        let pub_key = key.to_public_key().unwrap();
        let neg_pub_key = neg.to_public_key().unwrap();

        let sig = key.sign(&tbs).unwrap();
        assert!(
            pub_key.verify(tbs.as_ref(), &sig).is_ok(),
            "algorithm: {:?}",
            key.algorithm(),
        );

        let pub_key = key.to_public_key().unwrap();
        let dns_key = DNSKEY::from_key(&pub_key);
        assert!(
            dns_key.verify(tbs.as_ref(), &sig).is_ok(),
            "algorithm: {:?} (dnskey)",
            pub_key.algorithm(),
        );
        assert!(
            neg_pub_key.verify(tbs.as_ref(), &sig).is_err(),
            "algorithm: {:?} (neg)",
            neg_pub_key.algorithm(),
        );

        let neg_pub_key = neg.to_public_key().unwrap();
        let neg_dns_key = DNSKEY::from_key(&neg_pub_key);
        assert!(
            neg_dns_key.verify(tbs.as_ref(), &sig).is_err(),
            "algorithm: {:?} (dnskey, neg)",
            neg_pub_key.algorithm(),
        );
    }
}
