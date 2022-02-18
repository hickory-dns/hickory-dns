// Copyright 2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SSHFP records for SSH public key fingerprints
use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use data_encoding::{Encoding, Specification};
use lazy_static::lazy_static;

use crate::error::*;
use crate::serialize::binary::*;

lazy_static! {
    /// HEX formatting specific to TLSA and SSHFP encodings
    pub static ref HEX: Encoding = {
        let mut spec = Specification::new();
        spec.symbols.push_str("0123456789abcdef");
        spec.ignore.push_str(" \t\r\n");
        spec.translate.from.push_str("ABCDEF");
        spec.translate.to.push_str("abcdef");
        spec.encoding().expect("error in sshfp HEX encoding")
    };
}

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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SSHFP {
    algorithm: Algorithm,
    fingerprint_type: FingerprintType,
    fingerprint: Vec<u8>,
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

    /// The SSH public key algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The fingerprint type to use.
    pub fn fingerprint_type(&self) -> FingerprintType {
        self.fingerprint_type
    }

    /// The fingerprint of the public key.
    pub fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum FingerprintType {
    /// Reserved value
    Reserved,

    /// SHA-1
    SHA1,

    /// SHA-256
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

/// Read the RData from the given decoder.
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<SSHFP> {
    let algorithm = decoder.read_u8()?.unverified().into();
    let fingerprint_type = decoder.read_u8()?.unverified().into();
    let fingerprint_len = rdata_length
        .map(|l| l as usize)
        .checked_sub(2)
        .map_err(|_| ProtoError::from("invalid rdata length in SSHFP"))?
        .unverified();
    let fingerprint = decoder.read_vec(fingerprint_len)?.unverified();
    Ok(SSHFP::new(algorithm, fingerprint_type, fingerprint))
}

/// Write the RData using the given encoder.
pub fn emit(encoder: &mut BinEncoder<'_>, sshfp: &SSHFP) -> ProtoResult<()> {
    encoder.emit_u8(sshfp.algorithm().into())?;
    encoder.emit_u8(sshfp.fingerprint_type().into())?;
    encoder.emit_vec(sshfp.fingerprint())
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
        emit(&mut encoder, &rdata).expect("failed to emit SSHFP");
        let bytes = encoder.into_bytes();
        assert_eq!(bytes, &result);

        let mut decoder = BinDecoder::new(result);
        let read_rdata =
            read(&mut decoder, Restrict::new(result.len() as u16)).expect("failed to read SSHFP");
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
}
