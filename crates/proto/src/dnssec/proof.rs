// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNSSEC related Proof of record authenticity

use core::{fmt, ops::BitOr};

use bitflags::bitflags;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[must_use = "Proof is a flag on Record data, it should be interrogated before using a record"]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
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
    #[default]
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

    /// Either the record has not been verified or there were network issues fetching DNSSEC records
    #[inline]
    pub fn is_indeterminate(&self) -> bool {
        *self == Self::Indeterminate
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

impl core::error::Error for Proof {}

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
    /// use hickory_proto::dnssec::{Proof, Proven};
    ///
    /// let proven = Proven::new(Proof::Bogus, 42u32);
    ///
    /// assert_eq!(*proven.require_as_ref(Proof::Bogus).unwrap(), 42_u32);
    /// assert_eq!(*proven.require_as_ref(Proof::Bogus | Proof::Indeterminate).unwrap(), 42_u32);
    /// assert_eq!(proven.require_as_ref(Proof::Secure | Proof::Insecure).unwrap_err(), Proof::Bogus);
    /// ```
    pub fn require_as_ref<I: Into<ProofFlags>>(&self, flags: I) -> Result<&T, Proof> {
        if flags.into().contains(ProofFlags::from(self.proof)) {
            Ok(&self.value)
        } else {
            Err(self.proof)
        }
    }

    /// Attempts to take the value only if it matches flags, returning the associated proof on failure
    ///
    /// ```
    /// use hickory_proto::dnssec::{Proof, Proven};
    ///
    /// let proven = Proven::new(Proof::Bogus, 42u32);
    ///
    /// assert_eq!(proven.clone().require(Proof::Bogus).unwrap(), 42_u32);
    /// assert_eq!(proven.clone().require(Proof::Bogus | Proof::Indeterminate).unwrap(), 42_u32);
    /// assert!(proven.require(Proof::Secure | Proof::Insecure).is_err());
    /// ```
    pub fn require<I: Into<ProofFlags>>(self, flags: I) -> Result<T, Self> {
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
        Some(Proven {
            proof: self.proof,
            value: self.value?,
        })
    }
}
