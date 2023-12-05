// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNSSEC related Proof of record authenticity

use std::{fmt, ops::BitOr};

use bitflags::bitflags;
#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    error::{DnsSecError, ProtoError},
    op::Query,
    rr::{Name, RecordType},
};

use super::Algorithm;

/// Represents the status of a DNSSEC verified record.
///
/// see [RFC 4035, DNSSEC Protocol Modifications, March 2005](https://datatracker.ietf.org/doc/html/rfc4035#section-4.3)
/// ```text
/// 4.3.  Determining Security Status of Data
///
///   A security-aware resolver MUST be able to determine whether it should
///   expect a particular RRset to be signed.  More precisely, a
///   security-aware resolver must be able to distinguish between four
///   cases:
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[must_use = "Proof is a flag on Record data, it should be interrogated before using a record"]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Proof {
    /// An RRset for which the resolver is able to build a chain of
    ///   signed DNSKEY and DS RRs from a trusted security anchor to the
    ///   RRset.  In this case, the RRset should be signed and is subject to
    ///   signature validation, as described above.
    Secure = 3,

    /// An RRset for which the resolver knows that it has no chain
    ///   of signed DNSKEY and DS RRs from any trusted starting point to the
    ///   RRset.  This can occur when the target RRset lies in an unsigned
    ///   zone or in a descendent of an unsigned zone.  In this case, the
    ///   RRset may or may not be signed, but the resolver will not be able
    ///   to verify the signature.
    Insecure = 2,

    /// An RRset for which the resolver believes that it ought to be
    ///   able to establish a chain of trust but for which it is unable to
    ///   do so, either due to signatures that for some reason fail to
    ///   validate or due to missing data that the relevant DNSSEC RRs
    ///   indicate should be present.  This case may indicate an attack but
    ///   may also indicate a configuration error or some form of data
    ///   corruption.
    Bogus = 1,

    /// An RRset for which the resolver is not able to
    ///   determine whether the RRset should be signed, as the resolver is
    ///   not able to obtain the necessary DNSSEC RRs.  This can occur when
    ///   the security-aware resolver is not able to contact security-aware
    ///   name servers for the relevant zones.
    Indeterminate = 0,
}

impl Proof {
    /// Returns true if this Proof represents a validated DNSSEC record
    #[inline]
    pub fn is_secure(&self) -> bool {
        *self == Self::Secure
    }

    /// Returns true if this Proof represents a validated to be insecure DNSSEC record,
    ///   meaning the zone is known to be not signed
    #[inline]
    pub fn is_insecure(&self) -> bool {
        *self == Self::Insecure
    }

    /// Returns true if this Proof represents a DNSSEC record that failed validation,
    ///   meaning that the DNSSEC is bad, or other DNSSEC records are incorrect
    #[inline]
    pub fn is_bogus(&self) -> bool {
        *self == Self::Bogus
    }

    /// Either the record has not been verified or
    #[inline]
    pub fn is_indeterminate(&self) -> bool {
        *self == Self::Indeterminate
    }
}

impl Default for Proof {
    /// Returns `Indeterminate` as the default state for Proof as this is the closest to meaning
    ///   that no DNSSEC verification has happened.
    fn default() -> Self {
        Self::Indeterminate
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        };

        f.write_str(s)
    }
}

impl PartialOrd for Proof {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Proof {
    /// If self is great than other, it has a strong DNSSEC proof, i.e. Secure is the highest
    ///   Ordering from highest to lowest is: Secure, Insecure, Bogus, Indeterminate
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let this = *self as u8;
        let other = *other as u8;

        this.cmp(&other)
    }
}

impl std::error::Error for Proof {}

#[test]
fn test_order() {
    assert!(Proof::Secure > Proof::Insecure);
    assert!(Proof::Insecure > Proof::Bogus);
    assert!(Proof::Bogus > Proof::Indeterminate);
}

bitflags! {
    /// Represents a set of flags.
    pub struct ProofFlags: u32 {
        /// Represents Proof::Secure
        const SECURE = 1 << Proof::Secure as u8;
        /// Represents Proof::Insecure
        const INSECURE = 1 << Proof::Insecure as u8;
        /// Represents Proof::Bogus
        const BOGUS = 1 << Proof::Bogus as u8;
        /// Represents Proof::Indeterminate
        const INDETERMINATE = 1 << Proof::Indeterminate as u8;
    }
}

impl From<Proof> for ProofFlags {
    fn from(proof: Proof) -> Self {
        match proof {
            Proof::Secure => Self::SECURE,
            Proof::Insecure => Self::INSECURE,
            Proof::Bogus => Self::BOGUS,
            Proof::Indeterminate => Self::INDETERMINATE,
        }
    }
}

impl BitOr for Proof {
    type Output = ProofFlags;

    // rhs is the "right-hand side" of the expression `a | b`
    fn bitor(self, rhs: Self) -> Self::Output {
        ProofFlags::from(self) | ProofFlags::from(rhs)
    }
}

/// The error kind for dnssec errors that get returned in the crate
#[allow(unreachable_pub)]
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum ProofErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Algorithm mismatch between rrsig and dnskey
    #[error("algorithm mismatch rrsig: {rrsig} dnskey: {dnskey}")]
    AlgorithmMismatch {
        /// Algorithm specified in the RRSIG
        rrsig: Algorithm,
        /// Algorithm supported in the DNSKEY
        dnskey: Algorithm,
    },

    /// A DNSSEC validation error, occured
    #[error("ssl error: {0}")]
    DnsSecError(#[from] DnsSecError),

    /// A DnsKey verification of rrset and rrsig failed
    #[error("dnskey and rrset failed to verify: {name} key_tag: {key_tag}")]
    DnsKeyVerifyRrsig {
        /// The name/label of the DNSKEY
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
        /// The Error that occurred during validation
        error: ProtoError,
    },

    /// There was no DNSKEY found for verifying the DNSSEC of the zone
    #[error("no dnskey was found: {name}")]
    DnskeyNotFound {
        /// The name of the missing DNSKEY
        name: Name,
    },

    /// A DnsKey was revoked and could not be used for validation
    #[error("dnskey revoked: {name}, key_tag: {key_tag}")]
    DnsKeyRevoked {
        /// The name of the DNSKEY that was revoked
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
    },

    /// No DNSSEC records returned with for the DS record
    #[error("ds has no dnssec proof: {name}")]
    DsHasNoDnssecProof {
        /// DS record name
        name: Name,
    },

    /// DS record exists but not a DNSKEY that matches
    #[error("ds record exists, but no dnskey: {name}")]
    DsRecordsButNoDnskey {
        /// Name of the missing DNSKEY
        name: Name,
    },

    /// DS record parent exists, but child does not
    #[error("ds record should exist: {name}")]
    DsRecordShouldExist {
        /// Name fo the missing DS key
        name: Name,
    },

    /// The DS response was empty
    #[error("ds response empty: {name}")]
    DsResponseEmpty {
        /// No records for the DS query were returned
        name: Name,
    },

    /// DS record does not exist, and this was proven with an NSEC
    #[error("ds record does not exist: {name}")]
    DsResponseNsec {
        /// The name of the DS record
        name: Name,
    },

    /// The DnsKey is not marked as a zone key
    #[error("not a zone signing key: {name} key_tag: {key_tag}")]
    NotZoneDnsKey {
        /// Name of the DNSKEY
        name: Name,
        /// The key tag derived from the DNSKEY
        key_tag: u16,
    },

    /// There was a protocol error when looking up DNSSEC records
    #[error("communication failure for query: {query}: {proto}")]
    Proto {
        /// Query that failed
        query: Query,
        /// Resons fo the failure
        proto: ProtoError,
    },

    /// The RRSIGs for the rrset are not present.
    ///    It's indeterminate if DS records can't be found
    ///    It's bogus if the DS records are present
    #[error("rrsigs are not present for: {name} record_type: {record_type}")]
    RrsigsNotPresent {
        /// Name that RRSIGS are missing for
        name: Name,
        /// The record type in question
        record_type: RecordType,
    },

    /// The RRSIGs could not be verified or failed validation
    #[error("rrsigs were not able to be verified: {name}, type: {record_type}")]
    RrsigsUnverified {
        /// Name that RRSIGS failed for
        name: Name,
        /// The record type in question
        record_type: RecordType,
    },

    /// The self-signed dnskey is invalid
    #[error("self-signed dnskey is invalid: {name}")]
    SelfSignedKeyInvalid {
        /// Name of the DNSKEY
        name: Name,
    },
}

/// The error type for dnssec errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct ProofError {
    /// The proof derived from the failed state
    pub proof: Proof,
    /// The kind of error
    pub kind: ProofErrorKind,
}

impl ProofError {
    /// Create an error with the given Proof and Associated Error
    pub fn new(proof: Proof, kind: ProofErrorKind) -> Self {
        Self { proof, kind }
    }

    /// Get the kind of the error
    pub fn kind(&self) -> &ProofErrorKind {
        &self.kind
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.proof, self.kind)
    }
}

/// A wrapper type to ensure that the state of a DNSSEC proof is evaluated before use
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Proven<T> {
    proof: Proof,
    value: T,
}

impl<T> Proven<T> {
    /// Wrap the value with the given proof
    pub fn new(proof: Proof, value: T) -> Self {
        Self { proof, value }
    }

    /// Get the associated proof
    pub fn proof(&self) -> Proof {
        self.proof
    }

    /// Attempts to borrow the value only if it matches flags, returning the associated proof on failure
    ///
    /// ```
    /// use hickory_proto::rr::dnssec::{Proof, Proven};
    ///
    /// let proven = Proven::new(Proof::Bogus, 42u32);
    ///
    /// assert_eq!(*proven.try_borrow(Proof::Bogus).unwrap(), 42_u32);
    /// assert_eq!(*proven.try_borrow(Proof::Bogus | Proof::Indeterminate).unwrap(), 42_u32);
    /// assert_eq!(proven.try_borrow(Proof::Secure | Proof::Insecure).unwrap_err(), Proof::Bogus);
    /// ```
    pub fn try_borrow<I: Into<ProofFlags>>(&self, flags: I) -> Result<&T, Proof> {
        if flags.into().contains(ProofFlags::from(self.proof)) {
            Ok(&self.value)
        } else {
            Err(self.proof)
        }
    }

    /// Attempts to borrow the value only if it matches flags, returning the associated proof on failure
    ///
    /// ```
    /// use hickory_proto::rr::dnssec::{Proof, Proven};
    ///
    /// let proven = Proven::new(Proof::Bogus, 42u32);
    ///
    /// assert_eq!(proven.clone().try_take(Proof::Bogus).unwrap(), 42_u32);
    /// assert_eq!(proven.clone().try_take(Proof::Bogus | Proof::Indeterminate).unwrap(), 42_u32);
    /// assert!(proven.try_take(Proof::Secure | Proof::Insecure).is_err());
    /// ```
    pub fn try_take<I: Into<ProofFlags>>(self, flags: I) -> Result<T, Self> {
        if flags.into().contains(ProofFlags::from(self.proof)) {
            Ok(self.value)
        } else {
            Err(self)
        }
    }

    /// Map the value with the associated function, carrying forward the proof
    pub fn map<U, F>(self, f: F) -> Proven<U>
    where
        F: FnOnce(T) -> U,
    {
        Proven {
            proof: self.proof,
            value: f(self.value),
        }
    }

    /// Unwraps the Proven type into it's parts
    pub fn into_parts(self) -> (Proof, T) {
        let Self { proof, value } = self;

        (proof, value)
    }
}

impl<T> Proven<Option<T>> {
    /// If the inner type is an Option this will transpose them so that it's an option wrapped Proven
    pub fn transpose(self) -> Option<Proven<T>> {
        if let Some(value) = self.value {
            Some(Proven {
                proof: self.proof,
                value,
            })
        } else {
            None
        }
    }
}
