// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
// Copyright 2024 Brian Taber <btaber@zsd.systems>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// needed for the derive statements on algorithm
//   this issue in rustc would help narrow the statement: https://github.com/rust-lang/rust/issues/62398
#![allow(deprecated, clippy::use_self)]

use alloc::fmt;
use core::fmt::{Display, Formatter};
use core::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::serialize::binary::*;
use crate::serialize::txt::ParseError;

/// An identifier from the [DNS Security Algorithm Numbers] registry.
///
/// CERT records use the same identifiers. In a CERT record, zero means that the certificate's
/// algorithm is unknown to DNSSEC (see [RFC 4398 section 2]).
///
/// [DNS Security Algorithm Numbers]: https://www.iana.org/assignments/dns-sec-alg-numbers/
/// [RFC 4398 section 2]: https://www.rfc-editor.org/rfc/rfc4398#section-2
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
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
    #[cfg_attr(
        feature = "serde",
        serde(rename = "RSASHA1-NSEC3-SHA1", alias = "RSASHA1NSEC3SHA1")
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
    /// [RFC 8080](https://datatracker.ietf.org/doc/html/rfc8080)
    ED25519,
    /// An unrecognized algorithm number, including zero.
    #[cfg_attr(feature = "serde", serde(alias = "Reserved", alias = "Unassigned"))]
    Unknown(u8),
    /// Diffie-Hellman.
    DH,
    /// Elliptic curve cryptography.
    ECC,
    /// DSA/SHA-1 with NSEC3.
    DSANSEC3SHA1,
    /// GOST R 34.10-2001.
    ECCGOST,
    /// Ed448.
    ED448,
    /// SM2 with SM3.
    SM2SM3,
    /// GOST R 34.10-2012.
    ECCGOST12,
    /// Indirect key.
    INDIRECT,
    /// Private algorithm identified by a DNS name.
    PRIVATEDNS,
    /// Private algorithm identified by an object identifier.
    PRIVATEOID,
}

impl Algorithm {
    /// <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>
    pub fn from_u8(value: u8) -> Self {
        Self::from(value)
    }

    /// Whether this algorithm is supported by hickory's build settings
    #[cfg(feature = "__dnssec")]
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            Algorithm::ECDSAP256SHA256
                | Algorithm::ECDSAP384SHA384
                | Algorithm::ED25519
                | Algorithm::RSASHA1
                | Algorithm::RSASHA1NSEC3SHA1
                | Algorithm::RSASHA256
                | Algorithm::RSASHA512
        )
    }

    /// length in bytes that the hash portion of this function will produce
    pub fn hash_len(self) -> Option<usize> {
        match self {
            Self::RSAMD5 => Some(16),                                       // 128 bits
            Self::DSA | Self::RSASHA1 | Self::RSASHA1NSEC3SHA1 => Some(20), // 160 bits
            Self::RSASHA256 | Self::ECDSAP256SHA256 | Self::ED25519 => Some(32), // 256 bits
            Self::ECDSAP384SHA384 => Some(48),
            Self::RSASHA512 => Some(64), // 512 bites
            _ => None,
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
            Self::DH => "DH",
            Self::ECC => "ECC",
            Self::DSANSEC3SHA1 => "DSA-NSEC3-SHA1",
            Self::ECCGOST => "ECC-GOST",
            Self::ED448 => "ED448",
            Self::SM2SM3 => "SM2SM3",
            Self::ECCGOST12 => "ECC-GOST12",
            Self::INDIRECT => "INDIRECT",
            Self::PRIVATEDNS => "PRIVATEDNS",
            Self::PRIVATEOID => "PRIVATEOID",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl BinEncodable for Algorithm {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        u8::from(*self).emit(encoder)
    }
}

impl<'r> BinDecodable<'r> for Algorithm {
    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    fn read(decoder: &mut BinDecoder<'r>) -> Result<Self, DecodeError> {
        let algorithm_id =
            decoder.read_u8()?.unverified(/*Algorithm is verified as safe in processing this*/);
        Ok(Self::from_u8(algorithm_id))
    }
}

impl From<u8> for Algorithm {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RSAMD5,
            2 => Self::DH,
            3 => Self::DSA,
            4 => Self::ECC,
            5 => Self::RSASHA1,
            6 => Self::DSANSEC3SHA1,
            7 => Self::RSASHA1NSEC3SHA1,
            8 => Self::RSASHA256,
            10 => Self::RSASHA512,
            12 => Self::ECCGOST,
            13 => Self::ECDSAP256SHA256,
            14 => Self::ECDSAP384SHA384,
            15 => Self::ED25519,
            16 => Self::ED448,
            17 => Self::SM2SM3,
            23 => Self::ECCGOST12,
            252 => Self::INDIRECT,
            253 => Self::PRIVATEDNS,
            254 => Self::PRIVATEOID,
            _ => Self::Unknown(value),
        }
    }
}

impl FromStr for Algorithm {
    type Err = ParseError;

    /// Parses an algorithm from its decimal value or its DNSSEC mnemonic
    /// ([RFC 4398 section 2.2](https://datatracker.ietf.org/doc/html/rfc4398#section-2.2))
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(value) = u8::from_str(s) {
            return Ok(Self::from(value));
        }

        Ok(match s {
            s if s.eq_ignore_ascii_case("RSAMD5") => Self::RSAMD5,
            s if s.eq_ignore_ascii_case("DH") => Self::DH,
            s if s.eq_ignore_ascii_case("DSA") => Self::DSA,
            s if s.eq_ignore_ascii_case("ECC") => Self::ECC,
            s if s.eq_ignore_ascii_case("RSASHA1") => Self::RSASHA1,
            s if s.eq_ignore_ascii_case("DSA-NSEC3-SHA1") || s.eq_ignore_ascii_case("NSEC3DSA") => {
                Self::DSANSEC3SHA1
            }
            s if s.eq_ignore_ascii_case("RSASHA1-NSEC3-SHA1")
                || s.eq_ignore_ascii_case("NSEC3RSASHA1") =>
            {
                Self::RSASHA1NSEC3SHA1
            }
            s if s.eq_ignore_ascii_case("RSASHA256") => Self::RSASHA256,
            s if s.eq_ignore_ascii_case("RSASHA512") => Self::RSASHA512,
            s if s.eq_ignore_ascii_case("ECC-GOST") || s.eq_ignore_ascii_case("ECCGOST") => {
                Self::ECCGOST
            }
            s if s.eq_ignore_ascii_case("ECDSAP256SHA256") => Self::ECDSAP256SHA256,
            s if s.eq_ignore_ascii_case("ECDSAP384SHA384") => Self::ECDSAP384SHA384,
            s if s.eq_ignore_ascii_case("ED25519") => Self::ED25519,
            s if s.eq_ignore_ascii_case("ED448") => Self::ED448,
            s if s.eq_ignore_ascii_case("SM2SM3") => Self::SM2SM3,
            s if s.eq_ignore_ascii_case("ECC-GOST12") || s.eq_ignore_ascii_case("ECCGOST12") => {
                Self::ECCGOST12
            }
            s if s.eq_ignore_ascii_case("INDIRECT") => Self::INDIRECT,
            s if s.eq_ignore_ascii_case("PRIVATEDNS") => Self::PRIVATEDNS,
            s if s.eq_ignore_ascii_case("PRIVATEOID") => Self::PRIVATEOID,
            _ => return Err(ParseError::from("Invalid digit found in algorithm token")),
        })
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
            Algorithm::DH => 2,
            Algorithm::DSA => 3,
            Algorithm::ECC => 4,
            Algorithm::RSASHA1 => 5,
            Algorithm::DSANSEC3SHA1 => 6,
            Algorithm::RSASHA1NSEC3SHA1 => 7,
            Algorithm::RSASHA256 => 8,
            Algorithm::RSASHA512 => 10,
            Algorithm::ECCGOST => 12,
            Algorithm::ECDSAP256SHA256 => 13,
            Algorithm::ECDSAP384SHA384 => 14,
            Algorithm::ED25519 => 15,
            Algorithm::ED448 => 16,
            Algorithm::SM2SM3 => 17,
            Algorithm::ECCGOST12 => 23,
            Algorithm::INDIRECT => 252,
            Algorithm::PRIVATEDNS => 253,
            Algorithm::PRIVATEOID => 254,
            Algorithm::Unknown(v) => v,
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        // Use decimal form when zone file parsers disagree on the mnemonic.
        match self {
            Self::ECC
            | Self::DSANSEC3SHA1
            | Self::RSASHA1NSEC3SHA1
            | Self::ECCGOST
            | Self::SM2SM3
            | Self::ECCGOST12
            | Self::Unknown(_) => write!(f, "{}", u8::from(*self)),
            _ => f.write_str(self.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trip() {
        for value in 0..=u8::MAX {
            let algorithm = Algorithm::from_bytes(&[value]).unwrap();
            assert_eq!(algorithm.to_bytes().unwrap(), [value]);
        }
    }

    #[test]
    fn parse_registered_algorithms() {
        for (mnemonic, value) in [
            ("RSAMD5", 1),
            ("DH", 2),
            ("DSA", 3),
            ("ECC", 4),
            ("RSASHA1", 5),
            ("DSA-NSEC3-SHA1", 6),
            ("RSASHA1-NSEC3-SHA1", 7),
            ("RSASHA256", 8),
            ("RSASHA512", 10),
            ("ECC-GOST", 12),
            ("ECDSAP256SHA256", 13),
            ("ECDSAP384SHA384", 14),
            ("ED25519", 15),
            ("ED448", 16),
            ("SM2SM3", 17),
            ("ECC-GOST12", 23),
            ("INDIRECT", 252),
            ("PRIVATEDNS", 253),
            ("PRIVATEOID", 254),
        ] {
            let algorithm = Algorithm::from(value);
            assert_eq!(algorithm.as_str(), mnemonic);
            assert_eq!(mnemonic.parse::<Algorithm>().unwrap(), algorithm);
        }

        for (alias, value) in [
            ("nsec3dsa", 6),
            ("NSEC3RSASHA1", 7),
            ("eccgost", 12),
            ("ECCGOST12", 23),
        ] {
            assert_eq!(alias.parse::<Algorithm>().unwrap(), Algorithm::from(value));
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
}
