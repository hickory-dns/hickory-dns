// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// needed for the derive statements on algorithm
//   this issue in rustc would help narrow the statement: https://github.com/rust-lang/rust/issues/62398
#![allow(deprecated, clippy::use_self)]

use std::fmt;
use std::fmt::{Display, Formatter};

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::serialize::binary::*;

/// DNSSec signing and validation algorithms.
///
/// For [reference](http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
///  the iana documents have all the officially registered algorithms.
///
/// [RFC 6944](https://tools.ietf.org/html/rfc6944), DNSSEC DNSKEY Algorithm Status, April 2013
///
/// ```text
///
/// 2.2.  Algorithm Implementation Status Assignment Rationale
///
/// RSASHA1 has an implementation status of Must Implement, consistent
/// with [RFC4034].  RSAMD5 has an implementation status of Must Not
/// Implement because of known weaknesses in MD5.
///
/// The status of RSASHA1-NSEC3-SHA1 is set to Recommended to Implement
/// as many deployments use NSEC3.  The status of RSA/SHA-256 and RSA/
/// SHA-512 are also set to Recommended to Implement as major deployments
/// (such as the root zone) use these algorithms [ROOTDPS].  It is
/// believed that RSA/SHA-256 or RSA/SHA-512 algorithms will replace
/// older algorithms (e.g., RSA/SHA-1) that have a perceived weakness.
///
/// Likewise, ECDSA with the two identified curves (ECDSAP256SHA256 and
/// ECDSAP384SHA384) is an algorithm that may see widespread use due to
/// the perceived similar level of security offered with smaller key size
/// compared to the key sizes of algorithms such as RSA.  Therefore,
/// ECDSAP256SHA256 and ECDSAP384SHA384 are Recommended to Implement.
///
/// All other algorithms used in DNSSEC specified without an
/// implementation status are currently set to Optional.
///
/// 2.3.  DNSSEC Implementation Status Table
///
/// The DNSSEC algorithm implementation status table is listed below.
/// Only the algorithms already specified for use with DNSSEC at the time
/// of writing are listed.
///
///  +------------+------------+-------------------+-------------------+
///  |    Must    |  Must Not  |    Recommended    |      Optional     |
///  |  Implement | Implement  |   to Implement    |                   |
///  +------------+------------+-------------------+-------------------+
///  |            |            |                   |                   |
///  |   RSASHA1  |   RSAMD5   |   RSASHA256       |   Any             |
///  |            |            |   RSASHA1-NSEC3   |   registered      |
///  |            |            |    -SHA1          |   algorithm       |
///  |            |            |   RSASHA512       |   not listed in   |
///  |            |            |   ECDSAP256SHA256 |   this table      |
///  |            |            |   ECDSAP384SHA384 |                   |
///  +------------+------------+-------------------+-------------------+
///
///    This table does not list the Reserved values in the IANA registry
///    table or the values for INDIRECT (252), PRIVATE (253), and PRIVATEOID
///    (254).  These values may relate to more than one algorithm and are
///    therefore up to the implementer's discretion.  As noted, any
///    algorithm not listed in the table is Optional.  As of this writing,
///    the Optional algorithms are DSASHA1, DH, DSA-NSEC3-SHA1, and GOST-
///    ECC, but in general, anything not explicitly listed is Optional.
///
/// 2.4.  Specifying New Algorithms and Updating the Status of Existing
///       Entries
///
///    [RFC6014] establishes a parallel procedure for adding a registry
///    entry for a new algorithm other than a standards track document.
///    Because any algorithm not listed in the foregoing table is Optional,
///    algorithms entered into the registry using the [RFC6014] procedure
///    are automatically Optional.
///
///    It has turned out to be useful for implementations to refer to a
///    single document that specifies the implementation status of every
///    algorithm.  Accordingly, when a new algorithm is to be registered
///    with a status other than Optional, this document shall be made
///    obsolete by a new document that adds the new algorithm to the table
///    in Section 2.3.  Similarly, if the status of any algorithm in the
///    table in Section 2.3 changes, a new document shall make this document
///    obsolete; that document shall include a replacement of the table in
///    Section 2.3.  This way, the goal of having one authoritative document
///    to specify all the status values is achieved.
///
///    This document cannot be updated, only made obsolete and replaced by a
///    successor document.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum Algorithm {
    /// DO NOT USE, MD5 is a compromised hashing function, it is here for backward compatibility
    #[deprecated(
        note = "this is a compromised hashing function, it is here for backward compatibility"
    )]
    RSAMD5,
    /// DO NOT USE, DSA is a compromised hashing function, it is here for backward compatibility
    #[deprecated(
        note = "this is a compromised hashing function, it is here for backward compatibility"
    )]
    DSA,
    /// DO NOT USE, SHA1 is a compromised hashing function, it is here for backward compatibility
    #[deprecated(
        note = "this is a compromised hashing function, it is here for backward compatibility"
    )]
    RSASHA1,
    /// DO NOT USE, SHA1 is a compromised hashing function, it is here for backward compatibility
    #[deprecated(
        note = "this is a compromised hashing function, it is here for backward compatibility"
    )]
    RSASHA1NSEC3SHA1,
    /// RSA public key with SHA256 hash
    RSASHA256,
    /// RSA public key with SHA512 hash
    RSASHA512,
    /// [rfc6605](https://tools.ietf.org/html/rfc6605)
    ECDSAP256SHA256,
    /// [rfc6605](https://tools.ietf.org/html/rfc6605)
    ECDSAP384SHA384,
    /// [draft-ietf-curdle-dnskey-eddsa-03](https://tools.ietf.org/html/draft-ietf-curdle-dnskey-eddsa-03)
    ED25519,
    /// An unknown algorithm identifier
    Unknown(u8),
}

impl Algorithm {
    /// <http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
    pub fn from_u8(value: u8) -> Self {
        #[allow(deprecated)]
        match value {
            1 => Self::RSAMD5,
            3 => Self::DSA,
            5 => Self::RSASHA1,
            7 => Self::RSASHA1NSEC3SHA1,
            8 => Self::RSASHA256,
            10 => Self::RSASHA512,
            13 => Self::ECDSAP256SHA256,
            14 => Self::ECDSAP384SHA384,
            15 => Self::ED25519,
            _ => Self::Unknown(value),
        }
    }

    /// length in bytes that the hash portion of this function will produce
    pub fn hash_len(self) -> Option<usize> {
        match self {
            Self::RSAMD5 => Some(16),                                       // 128 bits
            Self::DSA | Self::RSASHA1 | Self::RSASHA1NSEC3SHA1 => Some(20), // 160 bits
            Self::RSASHA256 | Self::ECDSAP256SHA256 | Self::ED25519 => Some(32), // 256 bits
            Self::ECDSAP384SHA384 => Some(48),
            Self::RSASHA512 => Some(64), // 512 bites
            Self::Unknown(_) => None,
        }
    }

    /// Convert to string form
    #[deprecated(note = "use as_str instead")]
    pub fn to_str(self) -> &'static str {
        self.as_str()
    }

    /// Convert to string form
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RSAMD5 => "RSAMD5",
            Self::DSA => "DSA",
            Self::RSASHA1 => "RSASHA1",
            Self::RSASHA256 => "RSASHA256",
            Self::RSASHA1NSEC3SHA1 => "RSASHA1-NSEC3-SHA1",
            Self::RSASHA512 => "RSASHA512",
            Self::ECDSAP256SHA256 => "ECDSAP256SHA256",
            Self::ECDSAP384SHA384 => "ECDSAP384SHA384",
            Self::ED25519 => "ED25519",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl BinEncodable for Algorithm {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit(u8::from(*self))
    }
}

impl<'r> BinDecodable<'r> for Algorithm {
    // http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let algorithm_id =
            decoder.read_u8()?.unverified(/*Algorithm is verified as safe in processing this*/);
        Ok(Self::from_u8(algorithm_id))
    }
}

impl From<Algorithm> for &'static str {
    fn from(a: Algorithm) -> &'static str {
        a.as_str()
    }
}

impl From<Algorithm> for u8 {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::RSAMD5 => 1,
            Algorithm::DSA => 3,
            Algorithm::RSASHA1 => 5,
            Algorithm::RSASHA1NSEC3SHA1 => 7,
            Algorithm::RSASHA256 => 8,
            Algorithm::RSASHA512 => 10,
            Algorithm::ECDSAP256SHA256 => 13,
            Algorithm::ECDSAP384SHA384 => 14,
            Algorithm::ED25519 => 15,
            Algorithm::Unknown(v) => v,
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(self.as_str())
    }
}

#[test]
fn test_into() {
    for algorithm in &[
        Algorithm::RSAMD5,
        Algorithm::DSA,
        Algorithm::RSASHA1,
        Algorithm::RSASHA256,
        Algorithm::RSASHA1NSEC3SHA1,
        Algorithm::RSASHA512,
        Algorithm::ECDSAP256SHA256,
        Algorithm::ECDSAP384SHA384,
        Algorithm::ED25519,
    ] {
        assert_eq!(*algorithm, Algorithm::from_u8(Into::<u8>::into(*algorithm)))
    }
}

#[test]
fn test_order() {
    let mut algorithms = [
        Algorithm::RSAMD5,
        Algorithm::DSA,
        Algorithm::RSASHA1,
        Algorithm::RSASHA256,
        Algorithm::RSASHA1NSEC3SHA1,
        Algorithm::RSASHA512,
        Algorithm::ECDSAP256SHA256,
        Algorithm::ECDSAP384SHA384,
        Algorithm::ED25519,
    ];

    algorithms.sort();

    for (got, expect) in algorithms.iter().zip(
        [
            Algorithm::RSAMD5,
            Algorithm::DSA,
            Algorithm::RSASHA1,
            Algorithm::RSASHA1NSEC3SHA1,
            Algorithm::RSASHA256,
            Algorithm::RSASHA512,
            Algorithm::ECDSAP256SHA256,
            Algorithm::ECDSAP384SHA384,
            Algorithm::ED25519,
        ]
        .iter(),
    ) {
        assert_eq!(got, expect);
    }
}
