// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SSHFP records for SSH public key fingerprints
#![allow(clippy::use_self)]

use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use data_encoding::{Encoding, Specification};
use once_cell::sync::Lazy;

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::{
        binary::{BinDecoder, BinEncodable, BinEncoder, DecodeError, Restrict, RestrictedMath},
        txt::ParseError,
    },
};

/// HEX formatting specific to TLSA, SMIMEA and SSHFP encodings
pub static HEX: Lazy<Encoding> = Lazy::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789abcdef");
    spec.ignore.push_str(" \t\r\n");
    spec.translate.from.push_str("ABCDEF");
    spec.translate.to.push_str("abcdef");
    spec.encoding().expect("error in sshfp HEX encoding")
});

/// [RFC 4255](https://tools.ietf.org/html/rfc4255#section-3.1)
///
/// ```text
/// 3.1.  The SSHFP RDATA Format
///
///    The RDATA for a SSHFP RR consists of an algorithm number, fingerprint
///    type and the fingerprint of the public host key.
///
///        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |   algorithm   |    fp type    |                               /
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
///        /                                                               /
///        /                          fingerprint                          /
///        /                                                               /
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// 3.1.3.  Fingerprint
///
///    The fingerprint is calculated over the public key blob as described
///    in [7].
///
///    The message-digest algorithm is presumed to produce an opaque octet
///    string output, which is placed as-is in the RDATA fingerprint field.
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub struct SSHFP {
    /// The SSH public key algorithm.
    pub algorithm: Algorithm,

    /// The fingerprint type to use.
    pub fingerprint_type: FingerprintType,

    /// The fingerprint of the public key.
    pub fingerprint: Vec<u8>,
}

impl SSHFP {
    /// Creates a new SSHFP record data.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - the SSH public key algorithm.
    /// * `fingerprint_type` - the fingerprint type to use.
    /// * `fingerprint` - the fingerprint of the public key.
    pub fn new(
        algorithm: Algorithm,
        fingerprint_type: FingerprintType,
        fingerprint: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            fingerprint_type,
            fingerprint,
        }
    }

    /// Parse the RData from a set of Tokens
    ///
    /// [RFC 4255](https://tools.ietf.org/html/rfc4255#section-3.2)
    ///
    /// ```text
    /// 3.2.  Presentation Format of the SSHFP RR
    ///
    ///    The RDATA of the presentation format of the SSHFP resource record
    ///    consists of two numbers (algorithm and fingerprint type) followed by
    ///    the fingerprint itself, presented in hex, e.g.:
    ///
    ///        host.example.  SSHFP 2 1 123456789abcdef67890123456789abcdef67890
    ///
    ///    The use of mnemonics instead of numbers is not allowed.
    /// ```
    pub(crate) fn from_tokens<'i, I: Iterator<Item = &'i str>>(
        mut tokens: I,
    ) -> Result<Self, ParseError> {
        fn missing_field<E: From<ParseError>>(field: &str) -> E {
            ParseError::Msg(format!("SSHFP {field} field missing")).into()
        }
        let (algorithm, fingerprint_type) = {
            let mut parse_u8 = |field: &str| {
                tokens
                    .next()
                    .ok_or_else(|| missing_field(field))
                    .and_then(|t| t.parse::<u8>().map_err(ParseError::from))
            };
            (
                parse_u8("algorithm")?.into(),
                parse_u8("fingerprint type")?.into(),
            )
        };
        let fingerprint = HEX.decode(
            tokens
                .next()
                .filter(|fp| !fp.is_empty())
                .ok_or_else(|| missing_field::<ParseError>("fingerprint"))?
                .as_bytes(),
        )?;
        Some(Self::new(algorithm, fingerprint_type, fingerprint))
            .filter(|_| tokens.next().is_none())
            .ok_or(ParseError::Message("too many fields for SSHFP"))
    }
}

/// ```text
/// 3.1.1.  Algorithm Number Specification
///
///    This algorithm number octet describes the algorithm of the public
///    key.  The following values are assigned:
///
///           Value    Algorithm name
///           -----    --------------
///           0        reserved
///           1        RSA
///           2        DSS
///
///    Reserving other types requires IETF consensus [4].
/// ```
///
/// The algorithm values have been updated in
/// [RFC 6594](https://tools.ietf.org/html/rfc6594) and
/// [RFC 7479](https://tools.ietf.org/html/rfc7479) and
/// [RFC 8709](https://tools.ietf.org/html/rfc8709).
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Algorithm {
    /// Reserved value
    Reserved,

    /// RSA
    RSA,

    /// DSS/DSA
    DSA,

    /// ECDSA
    ECDSA,

    /// Ed25519
    Ed25519,

    /// Ed448
    Ed448,

    /// Unassigned value
    Unassigned(u8),
}

impl From<u8> for Algorithm {
    fn from(alg: u8) -> Self {
        match alg {
            0 => Self::Reserved,
            1 => Self::RSA,
            2 => Self::DSA,
            3 => Self::ECDSA,
            4 => Self::Ed25519, // TODO more (XMSS)
            6 => Self::Ed448,
            _ => Self::Unassigned(alg),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Reserved => 0,
            Algorithm::RSA => 1,
            Algorithm::DSA => 2,
            Algorithm::ECDSA => 3,
            Algorithm::Ed25519 => 4,
            Algorithm::Ed448 => 6,
            Algorithm::Unassigned(alg) => alg,
        }
    }
}

/// ```text
/// 3.1.2.  Fingerprint Type Specification
///
///    The fingerprint type octet describes the message-digest algorithm
///    used to calculate the fingerprint of the public key.  The following
///    values are assigned:
///
///           Value    Fingerprint type
///           -----    ----------------
///           0        reserved
///           1        SHA-1
///
///    Reserving other types requires IETF consensus [4].
///
///    For interoperability reasons, as few fingerprint types as possible
///    should be reserved.  The only reason to reserve additional types is
///    to increase security.
/// ```
///
/// The fingerprint type values have been updated in
/// [RFC 6594](https://tools.ietf.org/html/rfc6594).
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum FingerprintType {
    /// Reserved value
    Reserved,

    /// SHA-1
    #[cfg_attr(feature = "serde", serde(rename = "SHA-1"))]
    SHA1,

    /// SHA-256
    #[cfg_attr(feature = "serde", serde(rename = "SHA-256"))]
    SHA256,

    /// Unassigned value
    Unassigned(u8),
}

impl From<u8> for FingerprintType {
    fn from(ft: u8) -> Self {
        match ft {
            0 => Self::Reserved,
            1 => Self::SHA1,
            2 => Self::SHA256,
            _ => Self::Unassigned(ft),
        }
    }
}

impl From<FingerprintType> for u8 {
    fn from(fingerprint_type: FingerprintType) -> Self {
        match fingerprint_type {
            FingerprintType::Reserved => 0,
            FingerprintType::SHA1 => 1,
            FingerprintType::SHA256 => 2,
            FingerprintType::Unassigned(ft) => ft,
        }
    }
}

impl BinEncodable for SSHFP {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u8(self.algorithm.into())?;
        encoder.emit_u8(self.fingerprint_type.into())?;
        encoder.emit_slice(&self.fingerprint)
    }
}

impl<'r> RecordDataDecodable<'r> for SSHFP {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> Result<Self, DecodeError> {
        let algorithm = decoder.read_u8()?.unverified().into();
        let fingerprint_type = decoder.read_u8()?.unverified().into();
        let fingerprint_len = length
            .map(|l| l as usize)
            .checked_sub(2)
            .map_err(|len| DecodeError::IncorrectRDataLengthRead { read: 2, len })?
            .unverified();
        let fingerprint = decoder.read_vec(fingerprint_len)?.unverified();
        Ok(SSHFP::new(algorithm, fingerprint_type, fingerprint))
    }
}

impl RecordData for SSHFP {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::SSHFP(data) => Some(data),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::SSHFP
    }

    fn into_rdata(self) -> RData {
        RData::SSHFP(self)
    }
}

/// [RFC 4255](https://tools.ietf.org/html/rfc4255#section-3.2)
///
/// ```text
/// 3.2.  Presentation Format of the SSHFP RR
///
///    The RDATA of the presentation format of the SSHFP resource record
///    consists of two numbers (algorithm and fingerprint type) followed by
///    the fingerprint itself, presented in hex, e.g.:
///
///        host.example.  SSHFP 2 1 123456789abcdef67890123456789abcdef67890
///
///    The use of mnemonics instead of numbers is not allowed.
/// ```
impl fmt::Display for SSHFP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{algorithm} {ty} {fingerprint}",
            algorithm = u8::from(self.algorithm),
            ty = u8::from(self.fingerprint_type),
            fingerprint = HEX.encode(&self.fingerprint),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_algorithm() {
        assert_eq!(Algorithm::Reserved, 0.into());
        assert_eq!(Algorithm::RSA, 1.into());
        assert_eq!(Algorithm::DSA, 2.into());
        assert_eq!(Algorithm::ECDSA, 3.into());
        assert_eq!(Algorithm::Ed25519, 4.into());
        assert_eq!(Algorithm::Ed448, 6.into());
        assert_eq!(Algorithm::Unassigned(17), 17.into());
        assert_eq!(Algorithm::Unassigned(42), 42.into());

        assert_eq!(0u8, Algorithm::Reserved.into());
        assert_eq!(1u8, Algorithm::RSA.into());
        assert_eq!(2u8, Algorithm::DSA.into());
        assert_eq!(3u8, Algorithm::ECDSA.into());
        assert_eq!(4u8, Algorithm::Ed25519.into());
        assert_eq!(6u8, Algorithm::Ed448.into());
        assert_eq!(17u8, Algorithm::Unassigned(17).into());
        assert_eq!(42u8, Algorithm::Unassigned(42).into());
    }

    #[test]
    fn read_fingerprint_type() {
        assert_eq!(FingerprintType::Reserved, 0.into());
        assert_eq!(FingerprintType::SHA1, 1.into());
        assert_eq!(FingerprintType::SHA256, 2.into());
        assert_eq!(FingerprintType::Unassigned(12), 12.into());
        assert_eq!(FingerprintType::Unassigned(89), 89.into());

        assert_eq!(0u8, FingerprintType::Reserved.into());
        assert_eq!(1u8, FingerprintType::SHA1.into());
        assert_eq!(2u8, FingerprintType::SHA256.into());
        assert_eq!(12u8, FingerprintType::Unassigned(12).into());
        assert_eq!(89u8, FingerprintType::Unassigned(89).into());
    }

    fn test_encode_decode(rdata: SSHFP, result: &[u8]) {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        rdata.emit(&mut encoder).expect("failed to emit SSHFP");
        let bytes = encoder.into_bytes();
        assert_eq!(bytes, &result);

        let mut decoder = BinDecoder::new(result);
        let read_rdata = SSHFP::read_data(&mut decoder, Restrict::new(result.len() as u16))
            .expect("failed to read SSHFP");
        assert_eq!(read_rdata, rdata)
    }

    #[test]
    fn test_encode_decode_sshfp() {
        test_encode_decode(
            SSHFP::new(Algorithm::RSA, FingerprintType::SHA256, vec![]),
            &[1, 2],
        );
        test_encode_decode(
            SSHFP::new(
                Algorithm::ECDSA,
                FingerprintType::SHA1,
                vec![115, 115, 104, 102, 112],
            ),
            &[3, 1, 115, 115, 104, 102, 112],
        );
        test_encode_decode(
            SSHFP::new(
                Algorithm::Reserved,
                FingerprintType::Reserved,
                b"ssh fingerprint".to_vec(),
            ),
            &[
                0, 0, 115, 115, 104, 32, 102, 105, 110, 103, 101, 114, 112, 114, 105, 110, 116,
            ],
        );
        test_encode_decode(
            SSHFP::new(
                Algorithm::Unassigned(255),
                FingerprintType::Unassigned(13),
                vec![100, 110, 115, 115, 101, 99, 32, 100, 97, 110, 101],
            ),
            &[255, 13, 100, 110, 115, 115, 101, 99, 32, 100, 97, 110, 101],
        );
    }

    #[test]
    fn test_parsing() {
        assert!(SSHFP::from_tokens(core::iter::empty()).is_err());
        assert!(SSHFP::from_tokens(vec!["51", "13"].into_iter()).is_err());
        assert!(SSHFP::from_tokens(vec!["1", "-1"].into_iter()).is_err());
        assert!(SSHFP::from_tokens(vec!["1", "1", "abcd", "foo"].into_iter()).is_err());

        use crate::rr::rdata::sshfp::Algorithm::*;
        use crate::rr::rdata::sshfp::FingerprintType::*;
        use crate::rr::rdata::sshfp::{Algorithm, FingerprintType};

        fn test_parsing(input: Vec<&str>, a: Algorithm, ft: FingerprintType, f: &[u8]) {
            assert!(
                SSHFP::from_tokens(input.into_iter())
                    .map(|rd| rd == SSHFP::new(a, ft, f.to_vec()))
                    .unwrap_or(false)
            );
        }

        test_parsing(
            vec!["1", "1", "dd465c09cfa51fb45020cc83316fff21b9ec74ac"],
            RSA,
            SHA1,
            &[
                221, 70, 92, 9, 207, 165, 31, 180, 80, 32, 204, 131, 49, 111, 255, 33, 185, 236,
                116, 172,
            ],
        );
        test_parsing(
            vec![
                "1",
                "2",
                "b049f950d1397b8fee6a61e4d14a9acdc4721e084eff5460bbed80cfaa2ce2cb",
            ],
            RSA,
            SHA256,
            &[
                176, 73, 249, 80, 209, 57, 123, 143, 238, 106, 97, 228, 209, 74, 154, 205, 196,
                114, 30, 8, 78, 255, 84, 96, 187, 237, 128, 207, 170, 44, 226, 203,
            ],
        );
        test_parsing(
            vec!["2", "1", "3b6ba6110f5ffcd29469fc1ec2ee25d61718badd"],
            DSA,
            SHA1,
            &[
                59, 107, 166, 17, 15, 95, 252, 210, 148, 105, 252, 30, 194, 238, 37, 214, 23, 24,
                186, 221,
            ],
        );
        test_parsing(
            vec![
                "2",
                "2",
                "f9b8a6a460639306f1b38910456a6ae1018a253c47ecec12db77d7a0878b4d83",
            ],
            DSA,
            SHA256,
            &[
                249, 184, 166, 164, 96, 99, 147, 6, 241, 179, 137, 16, 69, 106, 106, 225, 1, 138,
                37, 60, 71, 236, 236, 18, 219, 119, 215, 160, 135, 139, 77, 131,
            ],
        );
        test_parsing(
            vec!["3", "1", "c64607a28c5300fec1180b6e417b922943cffcdd"],
            ECDSA,
            SHA1,
            &[
                198, 70, 7, 162, 140, 83, 0, 254, 193, 24, 11, 110, 65, 123, 146, 41, 67, 207, 252,
                221,
            ],
        );
        test_parsing(
            vec![
                "3",
                "2",
                "821eb6c1c98d9cc827ab7f456304c0f14785b7008d9e8646a8519de80849afc7",
            ],
            ECDSA,
            SHA256,
            &[
                130, 30, 182, 193, 201, 141, 156, 200, 39, 171, 127, 69, 99, 4, 192, 241, 71, 133,
                183, 0, 141, 158, 134, 70, 168, 81, 157, 232, 8, 73, 175, 199,
            ],
        );
        test_parsing(
            vec!["4", "1", "6b6f6165636874657266696e6765727072696e74"],
            Ed25519,
            SHA1,
            &[
                107, 111, 97, 101, 99, 104, 116, 101, 114, 102, 105, 110, 103, 101, 114, 112, 114,
                105, 110, 116,
            ],
        );
        test_parsing(
            vec![
                "4",
                "2",
                "a87f1b687ac0e57d2a081a2f282672334d90ed316d2b818ca9580ea384d92401",
            ],
            Ed25519,
            SHA256,
            &[
                168, 127, 27, 104, 122, 192, 229, 125, 42, 8, 26, 47, 40, 38, 114, 51, 77, 144,
                237, 49, 109, 43, 129, 140, 169, 88, 14, 163, 132, 217, 36, 1,
            ],
        );
    }
}
