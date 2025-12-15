// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! dns security extension related modules

use alloc::string::String;
use alloc::vec::Vec;
use core::slice;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dnssec::crypto::Digest;
use crate::error::ProtoError;
use crate::rr::{Name, RData, Record};
use crate::serialize::binary::{BinEncodable, BinEncoder, DecodeError, NameEncoding};

mod algorithm;
pub use algorithm::Algorithm;

/// Cryptographic backend implementations of DNSSEC traits.
pub mod crypto;

mod ec_public_key;

mod proof;
pub use proof::{Proof, ProofFlags, Proven};

mod public_key;
pub use public_key::{PublicKey, PublicKeyBuf};

pub mod rdata;
use rdata::tsig::TsigAlgorithm;

mod rsa_public_key;

mod signer;
pub use signer::SigSigner;

mod supported_algorithm;
pub use supported_algorithm::SupportedAlgorithms;

mod tbs;
pub use tbs::TBS;

mod trust_anchor;
pub use trust_anchor::TrustAnchors;

mod tsig;
pub use tsig::{TSigResponseContext, TSigner};

mod verifier;
pub use verifier::Verifier;

/// An iterator over record data with all data wrapped in a Proven type for dnssec validation
pub struct DnssecIter<'a>(slice::Iter<'a, Record<RData>>);

impl<'a> DnssecIter<'a> {
    /// Create a new DnssecIter from any iterator of Record references
    pub fn new(records: &'a [Record<RData>]) -> Self {
        Self(records.iter())
    }
}

impl<'a> Iterator for DnssecIter<'a> {
    type Item = Proven<&'a Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Proven::from)
    }
}

/// ```text
/// RFC 5155                         NSEC3                        March 2008
///
/// 11.  IANA Considerations
///
///    Although the NSEC3 and NSEC3PARAM RR formats include a hash algorithm
///    parameter, this document does not define a particular mechanism for
///    safely transitioning from one NSEC3 hash algorithm to another.  When
///    specifying a new hash algorithm for use with NSEC3, a transition
///    mechanism MUST also be defined.
///
///    This document updates the IANA registry "DOMAIN NAME SYSTEM
///    PARAMETERS" (https://www.iana.org/assignments/dns-parameters) in sub-
///    registry "TYPES", by defining two new types.  Section 3 defines the
///    NSEC3 RR type 50.  Section 4 defines the NSEC3PARAM RR type 51.
///
///    This document updates the IANA registry "DNS SECURITY ALGORITHM
///    NUMBERS -- per [RFC4035]"
///    (https://www.iana.org/assignments/dns-sec-alg-numbers).  Section 2
///    defines the aliases DSA-NSEC3-SHA1 (6) and RSASHA1-NSEC3-SHA1 (7) for
///    respectively existing registrations DSA and RSASHA1 in combination
///    with NSEC3 hash algorithm SHA1.
///
///    Since these algorithm numbers are aliases for existing DNSKEY
///    algorithm numbers, the flags that exist for the original algorithm
///    are valid for the alias algorithm.
///
///    This document creates a new IANA registry for NSEC3 flags.  This
///    registry is named "DNSSEC NSEC3 Flags".  The initial contents of this
///    registry are:
///
///      0   1   2   3   4   5   6   7
///    +---+---+---+---+---+---+---+---+
///    |   |   |   |   |   |   |   |Opt|
///    |   |   |   |   |   |   |   |Out|
///    +---+---+---+---+---+---+---+---+
///
///       bit 7 is the Opt-Out flag.
///
///       bits 0 - 6 are available for assignment.
///
///    Assignment of additional NSEC3 Flags in this registry requires IETF
///    Standards Action [RFC2434].
///
///    This document creates a new IANA registry for NSEC3PARAM flags.  This
///    registry is named "DNSSEC NSEC3PARAM Flags".  The initial contents of
///    this registry are:
///
///      0   1   2   3   4   5   6   7
///    +---+---+---+---+---+---+---+---+
///    |   |   |   |   |   |   |   | 0 |
///    +---+---+---+---+---+---+---+---+
///
///       bit 7 is reserved and must be 0.
///
///       bits 0 - 6 are available for assignment.
///
///    Assignment of additional NSEC3PARAM Flags in this registry requires
///    IETF Standards Action [RFC2434].
///
///    Finally, this document creates a new IANA registry for NSEC3 hash
///    algorithms.  This registry is named "DNSSEC NSEC3 Hash Algorithms".
///    The initial contents of this registry are:
///
///       0 is Reserved.
///
///       1 is SHA-1.
///
///       2-255 Available for assignment.
///
///    Assignment of additional NSEC3 hash algorithms in this registry
///    requires IETF Standards Action [RFC2434].
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Default)]
pub enum Nsec3HashAlgorithm {
    /// Hash for the Nsec3 records
    #[default]
    #[cfg_attr(feature = "serde", serde(rename = "SHA-1"))]
    SHA1,
}

impl Nsec3HashAlgorithm {
    /// ```text
    /// Laurie, et al.              Standards Track                    [Page 14]
    ///
    /// RFC 5155                         NSEC3                        March 2008
    ///
    /// Define H(x) to be the hash of x using the Hash Algorithm selected by
    ///    the NSEC3 RR, k to be the number of Iterations, and || to indicate
    ///    concatenation.  Then define:
    ///
    ///       IH(salt, x, 0) = H(x || salt), and
    ///
    ///       IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
    ///
    ///    Then the calculated hash of an owner name is
    ///
    ///       IH(salt, owner name, iterations),
    ///
    ///    where the owner name is in the canonical form, defined as:
    ///
    ///    The wire format of the owner name where:
    ///
    ///    1.  The owner name is fully expanded (no DNS name compression) and
    ///        fully qualified;
    ///
    ///    2.  All uppercase US-ASCII letters are replaced by the corresponding
    ///        lowercase US-ASCII letters;
    ///
    ///    3.  If the owner name is a wildcard name, the owner name is in its
    ///        original unexpanded form, including the "*" label (no wildcard
    ///        substitution);
    /// ```
    pub fn hash(self, salt: &[u8], name: &Name, iterations: u16) -> Result<Digest, ProtoError> {
        match self {
            // if there ever is more than just SHA1 support, this should be a genericized method
            Self::SHA1 => {
                let mut buf: Vec<u8> = Vec::new();
                {
                    let mut encoder = BinEncoder::new(&mut buf);
                    let mut encoder =
                        encoder.with_name_encoding(NameEncoding::UncompressedLowercase);
                    name.emit(&mut encoder)?;
                }

                Ok(Digest::iterated(salt, &buf, DigestType::SHA1, iterations)?)
            }
        }
    }
}

impl TryFrom<u8> for Nsec3HashAlgorithm {
    type Error = DecodeError;

    /// <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SHA1),
            // TODO: where/when is SHA2?
            _ => Err(DecodeError::UnknownNsec3HashAlgorithm(value)),
        }
    }
}

impl From<Nsec3HashAlgorithm> for u8 {
    fn from(a: Nsec3HashAlgorithm) -> Self {
        match a {
            Nsec3HashAlgorithm::SHA1 => 1,
        }
    }
}

/// DNSSEC Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms
///
/// [IANA Registry](https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml)
/// ```text
/// Value    Description           Status       Reference
///  0        Reserved              -            [RFC3658]
///  1        SHA-1                 MANDATORY    [RFC3658]
///  2        SHA-256               MANDATORY    [RFC4509]
///  3        GOST R 34.11-94       DEPRECATED   [RFC5933][Change the status of GOST Signature Algorithms in DNSSEC in the IETF stream to Historic]
///  4        SHA-384               OPTIONAL     [RFC6605]
///  5        GOST R 34.11-2012     OPTIONAL     [RFC9558]
///  6        SM3                   OPTIONAL     [RFC9563]
/// ```
///
/// <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum DigestType {
    /// [RFC 3658](https://tools.ietf.org/html/rfc3658)
    #[cfg_attr(feature = "serde", serde(rename = "SHA-1"))]
    SHA1,
    /// [RFC 4509](https://tools.ietf.org/html/rfc4509)
    #[cfg_attr(feature = "serde", serde(rename = "SHA-256"))]
    SHA256,
    /// [RFC 6605](https://tools.ietf.org/html/rfc6605)
    #[cfg_attr(feature = "serde", serde(rename = "SHA-384"))]
    SHA384,
    /// An unknown digest type
    Unknown(u8),
}

impl DigestType {
    /// Whether this is a supported digest type
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl From<u8> for DigestType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::SHA1,
            2 => Self::SHA256,
            4 => Self::SHA384,
            _ => Self::Unknown(value),
        }
    }
}

impl From<DigestType> for u8 {
    fn from(a: DigestType) -> Self {
        match a {
            DigestType::SHA1 => 1,
            DigestType::SHA256 => 2,
            DigestType::SHA384 => 4,
            DigestType::Unknown(other) => other,
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
pub type DnsSecResult<T> = ::core::result::Result<T, DnsSecError>;

/// The error kind for dnssec errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsSecError {
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
    RingKeyRejected(#[from] ring_like::KeyRejected),

    /// A ring error
    #[error("ring error: {0}")]
    RingUnspecified(#[from] ring_like::Unspecified),

    /// Tsig unsupported mac algorithm
    /// Supported algorithm documented in `TsigAlgorithm::supported` function.
    #[error("Tsig unsupported mac algorithm")]
    TsigUnsupportedMacAlgorithm(TsigAlgorithm),

    /// Tsig key verification failed
    #[error("Tsig key wrong key error")]
    TsigWrongKey,
}

impl From<String> for DnsSecError {
    fn from(msg: String) -> Self {
        Self::Msg(msg)
    }
}

impl From<&'static str> for DnsSecError {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg)
    }
}

impl Clone for DnsSecError {
    fn clone(&self) -> Self {
        use DnsSecError::*;
        match self {
            HmacInvalid => HmacInvalid,
            Message(msg) => Message(msg),
            Msg(msg) => Msg(msg.clone()),
            // foreign
            Proto(proto) => Proto(proto.clone()),
            RingKeyRejected(r) => Msg(format!("Ring rejected key: {r}")),
            RingUnspecified(_r) => RingUnspecified(ring_like::Unspecified),
            TsigUnsupportedMacAlgorithm(alg) => TsigUnsupportedMacAlgorithm(alg.clone()),
            TsigWrongKey => TsigWrongKey,
        }
    }
}

/// DNSSEC status of an answer
#[derive(Clone, Copy, Debug)]
pub enum DnssecSummary {
    /// All records have been DNSSEC validated
    Secure,
    /// At least one record is in the Bogus state
    Bogus,
    /// Insecure / Indeterminate (e.g. "Island of security")
    Insecure,
}

impl DnssecSummary {
    /// Whether the records have been DNSSEC validated or not
    pub fn from_records<'a>(records: impl Iterator<Item = &'a Record>) -> Self {
        let mut all_secure = None;
        for record in records {
            match record.proof() {
                Proof::Secure => {
                    all_secure.get_or_insert(true);
                }
                Proof::Bogus => return Self::Bogus,
                _ => all_secure = Some(false),
            }
        }

        if all_secure.unwrap_or(false) {
            Self::Secure
        } else {
            Self::Insecure
        }
    }
}

#[cfg(all(feature = "dnssec-aws-lc-rs", not(feature = "dnssec-ring")))]
pub(crate) use aws_lc_rs_impl as ring_like;
#[cfg(feature = "dnssec-ring")]
pub(crate) use ring_impl as ring_like;

#[cfg(feature = "dnssec-aws-lc-rs")]
#[cfg_attr(feature = "dnssec-ring", allow(unused_imports))]
pub(crate) mod aws_lc_rs_impl {
    pub(crate) use aws_lc_rs::{
        digest,
        error::{KeyRejected, Unspecified},
        hmac,
        rand::SystemRandom,
        rsa::PublicKeyComponents,
        signature::{
            self, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
            ED25519_PUBLIC_KEY_LEN, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA512, RsaKeyPair,
        },
    };
}

#[cfg(feature = "dnssec-ring")]
pub(crate) mod ring_impl {
    pub(crate) use ring::{
        digest,
        error::{KeyRejected, Unspecified},
        hmac,
        rand::SystemRandom,
        rsa::PublicKeyComponents,
        signature::{
            self, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
            ED25519_PUBLIC_KEY_LEN, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA512, RsaKeyPair,
        },
    };
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
