// Copyright 2024 Brian Taber <btaber@zsd.systems>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CERT record type for storing certificates in DNS
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::{
        binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, DecodeError, RDataEncoding},
        txt::ParseError,
    },
};

pub use crate::rr::algorithm::Algorithm;

/// [RFC 4398, Storing Certificates in DNS, November 1987](https://tools.ietf.org/html/rfc4398#section-2.1)
///
/// ```text
/// [2.1](https://datatracker.ietf.org/doc/html/rfc4398#section-2.1).  Certificate Type Values
///
///    The following values are defined or reserved:
///
///          Value  Mnemonic  Certificate Type
///          -----  --------  ----------------
///              0            Reserved
///              1  PKIX      X.509 as per PKIX
///              2  SPKI      SPKI certificate
///              3  PGP       OpenPGP packet
///              4  IPKIX     The URL of an X.509 data object
///              5  ISPKI     The URL of an SPKI certificate
///              6  IPGP      The fingerprint and URL of an OpenPGP packet
///              7  ACPKIX    Attribute Certificate
///              8  IACPKIX   The URL of an Attribute Certificate
///          9-252            Available for IANA assignment
///            253  URI       URI private
///            254  OID       OID private
///            255            Reserved
///      256-65279            Available for IANA assignment
///    65280-65534            Experimental
///          65535            Reserved
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CertType {
    /// 0            Reserved
    Reserved0,

    /// 1  PKIX      X.509 as per PKIX
    PKIX,

    /// 2  SPKI      SPKI certificate
    SPKI,

    /// 3  PGP       OpenPGP packet
    PGP,

    /// 4  IPKIX     The URL of an X.509 data object
    IPKIX,

    /// 5  ISPKI     The URL of an SPKI certificate
    ISPKI,

    /// 6  IPGP      The fingerprint and URL of an OpenPGP packet
    IPGP,

    /// 7  ACPKIX    Attribute Certificate
    ACPKIX,

    /// 8  IACPKIX   The URL of an Attribute Certificate
    IACPKIX,

    /// 253  URI       URI private
    URI,

    /// 254  OID       OID private
    OID,

    /// 255          Reserved
    Reserved255,

    /// 9-252, 256-65279            Available for IANA assignment
    Unassigned(u16),

    /// 65280-65534            Experimental
    Experimental(u16),

    /// 65535        Reserved
    Reserved65535,
}

impl From<u16> for CertType {
    fn from(cert_type: u16) -> Self {
        match cert_type {
            0 => Self::Reserved0,
            1 => Self::PKIX,
            2 => Self::SPKI,
            3 => Self::PGP,
            4 => Self::IPKIX,
            5 => Self::ISPKI,
            6 => Self::IPGP,
            7 => Self::ACPKIX,
            8 => Self::IACPKIX,
            9_u16..=252_u16 => Self::Unassigned(cert_type),
            253 => Self::URI,
            254 => Self::OID,
            255 => Self::Reserved255,
            256_u16..=65279_u16 => Self::Unassigned(cert_type),
            65280_u16..=65534_u16 => Self::Experimental(cert_type),
            65535 => Self::Reserved65535,
        }
    }
}

impl From<CertType> for u16 {
    fn from(cert_type: CertType) -> Self {
        match cert_type {
            CertType::Reserved0 => 0,
            CertType::PKIX => 1,
            CertType::SPKI => 2,
            CertType::PGP => 3,
            CertType::IPKIX => 4,
            CertType::ISPKI => 5,
            CertType::IPGP => 6,
            CertType::ACPKIX => 7,
            CertType::IACPKIX => 8,
            CertType::URI => 253,
            CertType::OID => 254,
            CertType::Reserved255 => 255,
            CertType::Unassigned(cert_type) => cert_type,
            CertType::Experimental(cert_type) => cert_type,
            CertType::Reserved65535 => 65535,
        }
    }
}

impl<'r> BinDecodable<'r> for CertType {
    fn read(decoder: &mut BinDecoder<'r>) -> Result<Self, DecodeError> {
        let algorithm_id = decoder
            .read_u16()?
            .unverified(/*CertType is verified as safe in processing this*/);
        Ok(Self::from(algorithm_id))
    }
}

impl FromStr for CertType {
    type Err = ParseError;

    /// Parses a certificate type from its decimal value or its mnemonic
    /// ([RFC 4398 section 2.2](https://datatracker.ietf.org/doc/html/rfc4398#section-2.2))
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(value) = u16::from_str(s) {
            return Ok(Self::from(value));
        }

        Ok(match s {
            s if s.eq_ignore_ascii_case("PKIX") => Self::PKIX,
            s if s.eq_ignore_ascii_case("SPKI") => Self::SPKI,
            s if s.eq_ignore_ascii_case("PGP") => Self::PGP,
            s if s.eq_ignore_ascii_case("IPKIX") => Self::IPKIX,
            s if s.eq_ignore_ascii_case("ISPKI") => Self::ISPKI,
            s if s.eq_ignore_ascii_case("IPGP") => Self::IPGP,
            s if s.eq_ignore_ascii_case("ACPKIX") => Self::ACPKIX,
            s if s.eq_ignore_ascii_case("IACPKIX") => Self::IACPKIX,
            s if s.eq_ignore_ascii_case("URI") => Self::URI,
            s if s.eq_ignore_ascii_case("OID") => Self::OID,
            _ => return Err(ParseError::from("Invalid digit found in cert_type token")),
        })
    }
}

impl fmt::Display for CertType {
    /// Writes the mnemonic of the certificate type if it has one, its decimal value otherwise
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PKIX => f.write_str("PKIX"),
            Self::SPKI => f.write_str("SPKI"),
            Self::PGP => f.write_str("PGP"),
            Self::IPKIX => f.write_str("IPKIX"),
            Self::ISPKI => f.write_str("ISPKI"),
            Self::IPGP => f.write_str("IPGP"),
            Self::ACPKIX => f.write_str("ACPKIX"),
            Self::IACPKIX => f.write_str("IACPKIX"),
            Self::URI => f.write_str("URI"),
            Self::OID => f.write_str("OID"),
            _ => write!(f, "{}", u16::from(*self)),
        }
    }
}

/// [RFC 4398, Storing Certificates in DNS, November 1987](https://tools.ietf.org/html/rfc4398)
///
/// ```text
///
/// [2](https://datatracker.ietf.org/doc/html/rfc4398#section-2).  The CERT Resource Record
///
///    The CERT resource record (RR) has the structure given below.  Its RR
///    type code is 37.
///
///       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |             type              |             key tag           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |   algorithm   |                                               /
///    +---------------+            certificate or CRL                 /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub struct CERT {
    /// The CERT type
    pub cert_type: CertType,

    /// The CERT key tag
    pub key_tag: u16,

    /// The CERT algorithm
    #[cfg_attr(feature = "serde", serde(with = "algorithm_serde"))]
    pub algorithm: Algorithm,

    /// The CERT record data
    ///
    /// The data stored here is **not** base64-encoded. Use the `cert_base64()` function
    /// if you need the data in base64-encoded format.
    pub cert_data: Vec<u8>,
}

impl CERT {
    /// Construct a new CERT RData
    pub const fn new(
        cert_type: CertType,
        key_tag: u16,
        algorithm: Algorithm,
        cert_data: Vec<u8>,
    ) -> Self {
        Self {
            cert_type,
            key_tag,
            algorithm,
            cert_data,
        }
    }

    /// Parse the RData from a set of Tokens
    pub(crate) fn from_tokens<'i, I: Iterator<Item = &'i str>>(
        tokens: I,
    ) -> Result<Self, ParseError> {
        let mut iter = tokens;

        let token = iter
            .next()
            .ok_or_else(|| ParseError::from("CERT cert type field missing"))?;
        let cert_type = CertType::from_str(token)?;

        let token = iter
            .next()
            .ok_or_else(|| ParseError::from("CERT key tag field missing"))?;
        let key_tag = u16::from_str(token)
            .map_err(|_| ParseError::from("Invalid digit found in key_tag token"))?;

        let token = iter
            .next()
            .ok_or_else(|| ParseError::from("CERT algorithm field missing"))?;
        let algorithm = Algorithm::from_str(token)?;

        // the base64 data may be split into several whitespace separated tokens
        let cert_data = iter.collect::<String>();
        if cert_data.is_empty() {
            return Err(ParseError::from("CERT data missing"));
        }

        let cert_data = data_encoding::BASE64
            .decode(cert_data.as_bytes())
            .map_err(|_| ParseError::from("Invalid base64 CERT data"))?;

        Ok(Self::new(cert_type, key_tag, algorithm, cert_data))
    }

    /// Returns the CERT (Base64)
    pub fn cert_base64(&self) -> String {
        data_encoding::BASE64.encode(&self.cert_data).clone()
    }
}

impl TryFrom<&[u8]> for CERT {
    type Error = DecodeError;

    fn try_from(cert_record: &[u8]) -> Result<Self, Self::Error> {
        let mut decoder = BinDecoder::new(cert_record);
        Self::read_data(&mut decoder) // Reuse the read_data method for parsing
    }
}

impl BinEncodable for CERT {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        let mut encoder = encoder.with_rdata_behavior(RDataEncoding::Other);
        u16::from(self.cert_type).emit(&mut encoder)?;
        self.key_tag.emit(&mut encoder)?;
        self.algorithm.emit(&mut encoder)?;
        encoder.emit_slice(&self.cert_data)?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for CERT {
    fn read_data(decoder: &mut BinDecoder<'r>) -> Result<Self, DecodeError> {
        let rdata_length = decoder.len();
        if rdata_length <= 5 {
            return Err(DecodeError::IncorrectRDataLengthRead {
                read: rdata_length,
                len: 6,
            });
        }

        // let cert_type = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let cert_type = CertType::read(decoder)?;
        let key_tag = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let algorithm = Algorithm::read(decoder)?;

        let cert_data = decoder.read_vec_to_end().unverified(/*will fail in usage if invalid*/);

        Ok(Self {
            cert_type,
            key_tag,
            algorithm,
            cert_data,
        })
    }
}

impl RecordData for CERT {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::CERT(data) => Some(data),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::CERT
    }

    fn into_rdata(self) -> RData {
        RData::CERT(self)
    }
}

/// [RFC 4398, Storing Certificates in DNS, November 1987](https://tools.ietf.org/html/rfc4398#section-2.2)
///
/// ```text
///
/// [2.2](https://datatracker.ietf.org/doc/html/rfc4398#section-2.2).  Text Representation of CERT RRs
///
///    The RDATA portion of a CERT RR has the type field as an unsigned
///    decimal integer or as a mnemonic symbol as listed in [Section 2.1](https://datatracker.ietf.org/doc/html/rfc4398#section-2.1),
///    above.
///
///    The key tag field is represented as an unsigned decimal integer.
///
///    The algorithm field is represented as an unsigned decimal integer or
///    a mnemonic symbol as listed in [[12](https://datatracker.ietf.org/doc/html/rfc4398#ref-12)].
///
///    The certificate/CRL portion is represented in base 64 [[16](https://datatracker.ietf.org/doc/html/rfc4398#ref-16)] and may be
///    divided into any number of white-space-separated substrings, down to
///    single base-64 digits, which are concatenated to obtain the full
///    signature.  These substrings can span lines using the standard
///    parenthesis.
///
///    Note that the certificate/CRL portion may have internal sub-fields,
///    but these do not appear in the master file representation.  For
///    example, with type 254, there will be an OID size, an OID, and then
///    the certificate/CRL proper.  However, only a single logical base-64
///    string will appear in the text representation.
///
/// ```
impl fmt::Display for CERT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let cert_data = &data_encoding::BASE64.encode(&self.cert_data);

        write!(
            f,
            "{cert_type} {key_tag} {algorithm} {cert_data}",
            cert_type = self.cert_type,
            key_tag = self.key_tag,
            algorithm = self.algorithm,
            cert_data = cert_data
        )?;

        Ok(())
    }
}

// CERT's original Serde enum used different variant indices from the DNSSEC enum.
// Keep that data format independent of the shared algorithm registry.
#[cfg(feature = "serde")]
mod algorithm_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Algorithm;

    macro_rules! cert_variants {
        ($($variant:ident),+ $(,)?) => {
            #[derive(Deserialize, Serialize)]
            #[serde(rename = "Algorithm")]
            enum Repr {
                Reserved(u8),
                $($variant,)+
                Unassigned(u8),
            }

            #[allow(deprecated)]
            impl From<Algorithm> for Repr {
                fn from(algorithm: Algorithm) -> Self {
                    match algorithm {
                        $(Algorithm::$variant => Self::$variant,)+
                        Algorithm::Unknown(n @ (0 | 9 | 11)) => Self::Reserved(n),
                        other => Self::Unassigned(u8::from(other)),
                    }
                }
            }

            #[allow(deprecated)]
            impl From<Repr> for Algorithm {
                fn from(repr: Repr) -> Self {
                    match repr {
                        $(Repr::$variant => Self::$variant,)+
                        Repr::Reserved(n) | Repr::Unassigned(n) => Self::from(n),
                    }
                }
            }
        };
    }

    cert_variants! {
        RSAMD5, DH, DSA, ECC, RSASHA1, INDIRECT, PRIVATEDNS, PRIVATEOID, DSANSEC3SHA1,
        RSASHA1NSEC3SHA1, RSASHA256, RSASHA512, ECCGOST, ECDSAP256SHA256, ECDSAP384SHA384,
        ED25519, ED448, SM2SM3, ECCGOST12,
    }

    pub(super) fn serialize<S: Serializer>(
        algorithm: &Algorithm,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Repr::from(*algorithm).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Algorithm, D::Error> {
        Repr::deserialize(deserializer).map(Algorithm::from)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_cert_type() {
        assert_eq!(CertType::Reserved0, CertType::from(0));
        assert_eq!(CertType::PKIX, CertType::from(1));
        assert_eq!(CertType::SPKI, CertType::from(2));
        assert_eq!(CertType::PGP, CertType::from(3));
        assert_eq!(CertType::IPKIX, CertType::from(4));
        assert_eq!(CertType::ISPKI, CertType::from(5));
        assert_eq!(CertType::IPGP, CertType::from(6));
        assert_eq!(CertType::ACPKIX, CertType::from(7));
        assert_eq!(CertType::IACPKIX, CertType::from(8));
        assert_eq!(CertType::URI, CertType::from(253));
        assert_eq!(CertType::OID, CertType::from(254));
        assert_eq!(CertType::Reserved255, CertType::from(255));
        assert_eq!(CertType::Unassigned(9), CertType::from(9));
        assert_eq!(CertType::Unassigned(90), CertType::from(90));
        assert_eq!(CertType::Experimental(65280), CertType::from(65280));
        assert_eq!(CertType::Experimental(65390), CertType::from(65390));
        assert_eq!(CertType::Reserved65535, CertType::from(65535));

        let cert_type_iana_9 = CertType::Unassigned(9);
        let cert_type_iana_90 = CertType::Unassigned(90);
        let cert_type_experimental_80 = CertType::Experimental(65280);
        let cert_type_experimental_90 = CertType::Experimental(65290);

        assert_eq!(u16::from(CertType::Reserved0), 0);
        assert_eq!(u16::from(CertType::PKIX), 1);
        assert_eq!(u16::from(CertType::SPKI), 2);
        assert_eq!(u16::from(CertType::PGP), 3);
        assert_eq!(u16::from(CertType::IPKIX), 4);
        assert_eq!(u16::from(CertType::ISPKI), 5);
        assert_eq!(u16::from(CertType::IPGP), 6);
        assert_eq!(u16::from(CertType::ACPKIX), 7);
        assert_eq!(u16::from(CertType::IACPKIX), 8);
        assert_eq!(u16::from(cert_type_iana_9), 9);
        assert_eq!(u16::from(cert_type_iana_90), 90);
        assert_eq!(u16::from(CertType::URI), 253);
        assert_eq!(u16::from(CertType::OID), 254);
        assert_eq!(u16::from(CertType::Reserved255), 255);
        assert_eq!(u16::from(cert_type_experimental_80), 65280);
        assert_eq!(u16::from(cert_type_experimental_90), 65290);
        assert_eq!(u16::from(CertType::Reserved65535), 65535);
    }

    #[test]
    fn test_valid_cert_data_length() {
        let valid_cert_data = [1, 2, 3, 4, 5, 6]; // At least 6 bytes
        let result = CERT::try_from(&valid_cert_data[..]);
        assert!(
            result.is_ok(),
            "Expected a valid result with sufficient cert_data length"
        );
    }

    #[test]
    fn test_cert_creation() {
        // Sample values
        let cert_type = CertType::PKIX;
        let key_tag = 12345;
        let algorithm = Algorithm::RSASHA256; // Replace with an actual variant from Algorithm
        let cert_data = [1, 2, 3, 4, 5];

        // Create an instance of the CERT struct
        let cert = CERT {
            cert_type,
            key_tag,
            algorithm,
            cert_data: cert_data.to_vec(),
        };

        // Assert that the fields are correctly set
        assert_eq!(cert.cert_type, cert_type);
        assert_eq!(cert.key_tag, key_tag);
        assert_eq!(cert.algorithm, algorithm);
        assert_eq!(cert.cert_data, cert_data);
    }

    #[test]
    fn test_cert_empty_cert_data() {
        let cert_type = CertType::PKIX;
        let key_tag = 12345;
        let algorithm = Algorithm::RSASHA256;
        let cert_data = Vec::new(); // Empty cert_data

        // Create an instance of the CERT struct
        let cert = CERT {
            cert_type,
            key_tag,
            algorithm,
            cert_data,
        };

        // Assert that cert_data is empty and other fields are correctly set
        assert_eq!(cert.cert_type, cert_type);
        assert_eq!(cert.key_tag, key_tag);
        assert_eq!(cert.algorithm, algorithm);
        assert!(cert.cert_data.is_empty());
    }

    #[test]
    fn test_valid_cert_record() {
        // Create a mock cert_data with 5 initial bytes + valid Base64 string for the rest
        let valid_cert_record = [
            0x00, 0x01, // cert_type: 1 (PKIX)
            0x30, 0x39, // key_tag: 12345
            0x08, // algorithm: 8 (e.g., RSASHA256)
            65, 81, 73, 68, // "AQID" = [1, 2, 3]
        ];

        let cert = CERT::try_from(&valid_cert_record[..]);
        assert!(cert.is_ok(), "Expected valid cert_record");

        let cert = cert.unwrap();
        assert_eq!(cert.cert_type, CertType::PKIX);
        assert_eq!(cert.key_tag, 12345);
        assert_eq!(cert.algorithm, Algorithm::RSASHA256); // Assuming this is algorithm 8
        assert_eq!(cert.cert_data, [65, 81, 73, 68]);
    }

    #[test]
    fn test_invalid_cert_record_length() {
        let invalid_cert_record = [1, 2, 3, 4]; // Less than 5 bytes

        let result = CERT::try_from(&invalid_cert_record[..]);
        assert!(
            matches!(
                result,
                Err(DecodeError::IncorrectRDataLengthRead { read: 4, len: 6 })
            ),
            "Expected error due to invalid cert_record length, got {result:?}"
        );
    }

    #[test]
    fn test_valid_cert_data() {
        // Base64-encoded dummy certificate data.
        let tokens = vec!["1", "123", "3", "Q2VydGlmaWNhdGUgZGF0YQ=="].into_iter();

        let result = CERT::from_tokens(tokens);

        assert!(result.is_ok());

        let cert = result.unwrap();
        assert_eq!(cert.cert_type, CertType::from(1));
        assert_eq!(cert.key_tag, 123);
        assert_eq!(cert.algorithm, Algorithm::from(3));
        assert_eq!(cert.cert_data, b"Certificate data".to_vec()); // Decoded base64 data.
    }

    #[test]
    fn test_invalid_base64_data() {
        // Invalid base64 data (contains invalid characters).
        let tokens = vec!["1", "123", "3", "Invalid_base64"].into_iter();

        let result = CERT::from_tokens(tokens);

        // Expecting an error for invalid base64 data.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(format!("{err}"), "Invalid base64 CERT data");
    }

    #[test]
    fn test_invalid_token_digit() {
        // Missing cert_type (first token) will try to decode cert leading to invalid digit
        let tokens = vec!["123", "3", "Q2VydGlmaWNhdGUgZGF0YQ=="].into_iter();

        let result = CERT::from_tokens(tokens);

        // Expecting an error due to missing cert type.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(format!("{err}"), "Invalid digit found in algorithm token");
    }

    #[test]
    fn test_missing_cert_data() {
        // Missing cert_data (last token)
        let tokens = vec!["1", "123", "3"].into_iter();

        let result = CERT::from_tokens(tokens);

        // Expecting an error due to missing cert data.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(format!("{err}"), "CERT data missing");
    }

    #[test]
    fn test_mnemonics_and_split_data() {
        let tokens = ["pgp", "7", "rsasha1", "Q2VydGlm", "aWNhdGUgZGF0YQ=="].into_iter();
        let cert = CERT::from_tokens(tokens).unwrap();
        assert_eq!(cert.cert_type, CertType::PGP);
        assert_eq!(u8::from(cert.algorithm), 5);
        assert_eq!(cert.cert_data, b"Certificate data".to_vec());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn legacy_algorithm_variant_indices() {
        use serde::de::value::{Error, U32Deserializer};

        for (index, algorithm) in [(1, 1), (6, 252), (11, 8), (19, 23)] {
            let value = U32Deserializer::<Error>::new(index);
            assert_eq!(
                algorithm_serde::deserialize(value).unwrap(),
                Algorithm::from(algorithm)
            );
        }
    }

    #[test]
    fn test_display_round_trip() {
        for (cert_type, algorithm, expected) in [
            (0, 0, "0 1 0 AQID"),
            (1, 7, "PKIX 1 7 AQID"),
            (1, 8, "PKIX 1 RSASHA256 AQID"),
            (1, 16, "PKIX 1 ED448 AQID"),
            (6, 6, "IPGP 1 6 AQID"),
            (9, 20, "9 1 20 AQID"),
            (253, 13, "URI 1 ECDSAP256SHA256 AQID"),
            (255, 252, "255 1 INDIRECT AQID"),
            (65280, 255, "65280 1 255 AQID"),
            (65535, 23, "65535 1 23 AQID"),
        ] {
            let cert = CERT::new(
                CertType::from(cert_type),
                1,
                Algorithm::from(algorithm),
                vec![1, 2, 3],
            );
            let text = cert.to_string();
            assert_eq!(text, expected);
            assert_eq!(CERT::from_tokens(text.split(' ')).unwrap(), cert);
        }
    }
}
