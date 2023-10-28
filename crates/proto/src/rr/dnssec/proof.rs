// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNSSEC related Proof of record authenticity

use std::fmt;

#[cfg(feature = "serde-config")]
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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Proof {
    /// An RRset for which the resolver is able to build a chain of
    ///   signed DNSKEY and DS RRs from a trusted security anchor to the
    ///   RRset.  In this case, the RRset should be signed and is subject to
    ///   signature validation, as described above.
    Secure,

    /// An RRset for which the resolver knows that it has no chain
    ///   of signed DNSKEY and DS RRs from any trusted starting point to the
    ///   RRset.  This can occur when the target RRset lies in an unsigned
    ///   zone or in a descendent of an unsigned zone.  In this case, the
    ///   RRset may or may not be signed, but the resolver will not be able
    ///   to verify the signature.
    Insecure,

    /// An RRset for which the resolver believes that it ought to be
    ///   able to establish a chain of trust but for which it is unable to
    ///   do so, either due to signatures that for some reason fail to
    ///   validate or due to missing data that the relevant DNSSEC RRs
    ///   indicate should be present.  This case may indicate an attack but
    ///   may also indicate a configuration error or some form of data
    ///   corruption.
    Bogus,

    /// An RRset for which the resolver is not able to
    ///   determine whether the RRset should be signed, as the resolver is
    ///   not able to obtain the necessary DNSSEC RRs.  This can occur when
    ///   the security-aware resolver is not able to contact security-aware
    ///   name servers for the relevant zones.
    Indeterminate,
}

impl Proof {
    /// Returns true if this Proof represents a validated DNSSEC record
    pub fn is_secure(&self) -> bool {
        *self == Self::Secure
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
