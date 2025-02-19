// Copyright 2024 Brian Taber <btaber@zsd.systems>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CERT record type for storing certificates in DNS
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::{ProtoError, ProtoResult},
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::binary::{
        BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict, RestrictedMath,
    },
};

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
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CertType {
    /// 0, 255, 65535            Reserved
    Reserved,

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

    /// 9-252, 256-65279            Available for IANA assignment
    Unassigned(u16),

    /// 65280-65534            Experimental
    Experimental(u16),
}

impl From<u16> for CertType {
    fn from(cert_type: u16) -> Self {
        match cert_type {
            0 => Self::Reserved,
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
            255 => Self::Reserved,
            256_u16..=65279_u16 => Self::Unassigned(cert_type),
            65280_u16..=65534_u16 => Self::Experimental(cert_type),
            65535 => Self::Reserved,
        }
    }
}

impl From<CertType> for u16 {
    fn from(cert_type: CertType) -> Self {
        match cert_type {
            CertType::Reserved => 0,
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
            CertType::Unassigned(cert_type) => cert_type,
            CertType::Experimental(cert_type) => cert_type,
        }
    }
}

impl<'r> BinDecodable<'r> for CertType {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let algorithm_id = decoder
            .read_u16()?
            .unverified(/*CertType is verified as safe in processing this*/);
        Ok(Self::from(algorithm_id))
    }
}

impl fmt::Display for CertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
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
/// [12]  Arends, R., Austein, R., Larson, M., Massey, D., and S. Rose,
/// "Resource Records for the DNS Security Extensions", RFC 4034,
/// March 2005.
///
///
/// [RFC 4034, Resource Records for the DNS Security Extensions, March 2005][rfc4034]
/// https://tools.ietf.org/html/rfc4034#appendix-A.1
///
/// [A.1](https://datatracker.ietf.org/doc/html/rfc4034#appendix-A.1).  DNSSEC Algorithm Types
///
///    The DNSKEY, RRSIG, and DS RRs use an 8-bit number to identify the
///    security algorithm being used.  These values are stored in the
///    "Algorithm number" field in the resource record RDATA.
///
///    Some algorithms are usable only for zone signing (DNSSEC), some only
///    for transaction security mechanisms (SIG(0) and TSIG), and some for
///    both.  Those usable for zone signing may appear in DNSKEY, RRSIG, and
///    DS RRs.  Those usable for transaction security would be present in
///    SIG(0) and KEY RRs, as described in [RFC2931].
///
///                                 Zone
///    Value Algorithm [Mnemonic]  Signing  References   Status
///    ----- -------------------- --------- ----------  ---------
///      0   reserved
///      1   RSA/MD5 [RSAMD5]         n      [RFC2537]  NOT RECOMMENDED
///      2   Diffie-Hellman [DH]      n      [RFC2539]   -
///      3   DSA/SHA-1 [DSA]          y      [RFC2536]  OPTIONAL
///      4   Elliptic Curve [ECC]              TBA       -
///      5   RSA/SHA-1 [RSASHA1]      y      [RFC3110]  MANDATORY
///    252   Indirect [INDIRECT]      n                  -
///    253   Private [PRIVATEDNS]     y      see below  OPTIONAL
///    254   Private [PRIVATEOID]     y      see below  OPTIONAL
///    255   reserved
///
///    6 - 251  Available for assignment by IETF Standards Action.
///
/// (RFC Required) Domain Name System Security (DNSSEC) Algorithm Numbers
/// Created: 2003-11-03, Last Updated: 2024-04-16
/// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.txt
///
///                                                              Zone
///     Value  Algorithm [Mnemonic]                            Signing    References
///     -----  --------------------                           ---------   ----------
///       6    DSA-NSEC3-SHA1 [DSA-NSEC3-SHA1]                    Y       [RFC5155][proposed standard]
///       7    RSASHA1-NSEC3-SHA1 [RSASHA1-NSEC3-SHA1]            Y       [RFC5155][proposed standard]
///       8    RSA/SHA-256 [RSASHA256]                            Y       [RFC5702][proposed standard]
///       9    reserved
///      10    RSA/SHA-512 [RSASHA512]                            Y       [RFC5702][proposed standard]
///      11    reserved
///      12    GOST R 34.10-2001 [ECC-GOST]                       Y       [RFC5933][proposed standard]
///      13    ECDSA Curve P-256 with SHA-256 [ECDSAP256SHA256]   Y       [RFC6605][proposed standard]
///      14    ECDSA Curve P-384 with SHA-384 [ECDSAP384SHA384]   Y       [RFC6605][proposed standard]
///      15    Ed25519 [ED25519]                                  Y       [RFC8080][proposed standard]
///      16    Ed448 [ED448]                                      Y       [RFC8080][proposed standard]
///      17    SM2 signing with SM3 hashing [SM2SM3]              Y       [RFC-cuiling-dnsop-sm2-alg-15][informational]
///   18-22    Unassigned
///      23    GOST R 34.10-2012 [ECC-GOST12]                     Y       [RFC9558][informational]
///  24-122    Unassigned
/// 123-251    reserved
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Algorithm {
    /// 0, 9, 11, 123-251, 255   reserved
    Reserved(u8),

    /// 1   RSA/MD5 ([RFC 2537](https://tools.ietf.org/html/rfc2537))
    RSAMD5,

    /// 2   Diffie-Hellman ([RFC 2539](https://tools.ietf.org/html/rfc2539))
    DH,

    /// 3   DSA/SHA-1 ([RFC 2536](https://tools.ietf.org/html/rfc2536))
    DSA,

    /// 4   Elliptic Curve
    ECC,

    /// 5   RSA/SHA-1 ([RFC 3110](https://tools.ietf.org/html/rfc3110))
    RSASHA1,

    /// 252   Indirect
    INDIRECT,

    /// 253   Private
    PRIVATEDNS,

    /// 254   Private
    PRIVATEOID,

    /// 6    DSA-NSEC3-SHA1 ([RFC 5155](https://tools.ietf.org/html/rfc5155))
    DSANSEC3SHA1,

    /// 7    RSASHA1-NSEC3-SHA1 (RFC5155)
    RSASHA1NSEC3SHA1,

    /// 8    RSA/SHA-256 ([RFC 5702](https://tools.ietf.org/html/rfc5702))
    RSASHA256,

    /// 10    RSA/SHA-512 ([RFC 5702](https://tools.ietf.org/html/rfc5702))
    RSASHA512,

    /// 12    GOST R 34.10-2001 ([RFC 5933](https://tools.ietf.org/html/rfc5933))
    ECCGOST,

    /// 13    ECDSA Curve P-256 with SHA-256 ([RFC 6605](https://tools.ietf.org/html/rfc6605))
    ECDSAP256SHA256,

    /// 14    ECDSA Curve P-384 with SHA-384 ([RFC 6605](https://tools.ietf.org/html/rfc6605))
    ECDSAP384SHA384,

    /// 15    Ed25519 ([RFC 8080](https://tools.ietf.org/html/rfc8080))
    ED25519,

    /// 16    Ed448 ([RFC 8080](https://tools.ietf.org/html/rfc8080))
    ED448,

    /// 17    SM2 signing with SM3 hashing (RFC-cuiling-dnsop-sm2-alg-15)
    SM2SM3,

    /// 23    GOST R 34.10-2012 ([RFC 9558](https://tools.ietf.org/html/rfc9558))
    ECCGOST12,

    ///   18-22, 24-122    Unassigned
    Unassigned(u8),
}

impl From<u8> for Algorithm {
    fn from(algorithm: u8) -> Self {
        match algorithm {
            0 => Self::Reserved(0),
            1 => Self::RSAMD5,
            2 => Self::DH,
            3 => Self::DSA,
            4 => Self::ECC,
            5 => Self::RSASHA1,
            6 => Self::DSANSEC3SHA1,
            7 => Self::RSASHA1NSEC3SHA1,
            8 => Self::RSASHA256,
            9 => Self::Reserved(9),
            10 => Self::RSASHA512,
            11 => Self::Reserved(11),
            12 => Self::ECCGOST,
            13 => Self::ECDSAP256SHA256,
            14 => Self::ECDSAP384SHA384,
            15 => Self::ED25519,
            16 => Self::ED448,
            17 => Self::SM2SM3,
            18..=22 => Self::Unassigned(algorithm),
            23 => Self::ECCGOST12,
            24..=122 => Self::Unassigned(algorithm),
            252 => Self::INDIRECT,
            253 => Self::PRIVATEDNS,
            254 => Self::PRIVATEOID,
            _ => Self::Unassigned(algorithm),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Reserved(value) if value == 0 => value,
            Algorithm::RSAMD5 => 1,
            Algorithm::DH => 2,
            Algorithm::DSA => 3,
            Algorithm::ECC => 4,
            Algorithm::RSASHA1 => 5,
            Algorithm::DSANSEC3SHA1 => 6,
            Algorithm::RSASHA1NSEC3SHA1 => 7,
            Algorithm::RSASHA256 => 8,
            Algorithm::Reserved(value) if value == 9 => value,
            Algorithm::RSASHA512 => 10,
            Algorithm::Reserved(value) if value == 11 => value,
            Algorithm::ECCGOST => 12,
            Algorithm::ECDSAP256SHA256 => 13,
            Algorithm::ECDSAP384SHA384 => 14,
            Algorithm::ED25519 => 15,
            Algorithm::ED448 => 16,
            Algorithm::SM2SM3 => 17,
            Algorithm::Unassigned(value) if (18..=22).contains(&value) => value,
            Algorithm::ECCGOST12 => 23,
            Algorithm::Unassigned(value) if (24..=122).contains(&value) => value,
            Algorithm::INDIRECT => 252,
            Algorithm::PRIVATEDNS => 253,
            Algorithm::PRIVATEOID => 254,
            Algorithm::Unassigned(value) => value,
            Algorithm::Reserved(value) => value,
        }
    }
}

impl<'r> BinDecodable<'r> for Algorithm {
    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let algorithm_id = decoder
            .read_u8()?
            .unverified(/*Algorithm is verified as safe in processing this*/);
        Ok(Self::from(algorithm_id))
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
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
pub struct CERT {
    cert_type: CertType,
    key_tag: u16,
    algorithm: Algorithm,
    cert_data: Vec<u8>,
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

    /// Returns the CERT type
    pub fn cert_type(&self) -> CertType {
        self.cert_type
    }

    /// Returns the CERT key tag
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Returns the CERT algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the CERT record data
    pub fn cert_data(&self) -> Vec<u8> {
        self.cert_data.clone()
    }

    /// Returns the CERT (Base64)
    pub fn cert_base64(&self) -> String {
        data_encoding::BASE64.encode(&self.cert_data).clone()
    }
}

impl TryFrom<&[u8]> for CERT {
    type Error = ProtoError;

    fn try_from(cert_record: &[u8]) -> Result<Self, Self::Error> {
        let mut decoder = BinDecoder::new(cert_record);
        let length = Restrict::new(cert_record.len() as u16); // You can use the full length here
        Self::read_data(&mut decoder, length) // Reuse the read_data method for parsing
    }
}

impl BinEncodable for CERT {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16(self.cert_type.into())?;
        encoder.emit_u16(self.key_tag)?;
        encoder.emit_u8(self.algorithm.into())?;
        encoder.emit_vec(&self.cert_data)?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for CERT {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let rdata_length = length.map(|u| u as usize).unverified(/*used only as length safely*/);

        if rdata_length <= 5 {
            return Err(ProtoError::from("invalid cert_record length".to_string()));
        }

        let start_idx = decoder.index();

        // let cert_type = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let cert_type = CertType::read(decoder)?;
        let key_tag = decoder.read_u16()?.unverified(/*valid as any u16*/);
        let algorithm = Algorithm::read(decoder)?;

        let cert_len = length
            .map(|u| u as usize)
            .checked_sub(decoder.index() - start_idx)
            .map_err(|_| ProtoError::from("invalid rdata length in CERT"))?
            .unverified(/*used only as length safely*/);

        let cert_data = decoder.read_vec(cert_len)?.unverified(/*will fail in usage if invalid*/);

        Ok(Self {
            cert_type,
            key_tag,
            algorithm,
            cert_data,
        })
    }
}

impl RecordData for CERT {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::CERT(data) => Ok(data),
            _ => Err(data),
        }
    }

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
            key_tag = &self.key_tag,
            algorithm = self.algorithm,
            cert_data = &cert_data
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test_cert_type() {
        assert_eq!(CertType::Reserved, CertType::from(0));
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
        assert_eq!(CertType::Unassigned(9), CertType::from(9));
        assert_eq!(CertType::Unassigned(90), CertType::from(90));
        assert_eq!(CertType::Experimental(65280), CertType::from(65280));
        assert_eq!(CertType::Experimental(65390), CertType::from(65390));

        let cert_type_ianna_9 = CertType::Unassigned(9);
        let cert_type_ianna_90 = CertType::Unassigned(90);
        let cert_type_experimental_80 = CertType::Experimental(65280);
        let cert_type_experimental_90 = CertType::Experimental(65290);

        assert_eq!(u16::from(CertType::Reserved), 0);
        assert_eq!(u16::from(CertType::PKIX), 1);
        assert_eq!(u16::from(CertType::SPKI), 2);
        assert_eq!(u16::from(CertType::PGP), 3);
        assert_eq!(u16::from(CertType::IPKIX), 4);
        assert_eq!(u16::from(CertType::ISPKI), 5);
        assert_eq!(u16::from(CertType::IPGP), 6);
        assert_eq!(u16::from(CertType::ACPKIX), 7);
        assert_eq!(u16::from(CertType::IACPKIX), 8);
        assert_eq!(u16::from(cert_type_ianna_9), 9);
        assert_eq!(u16::from(cert_type_ianna_90), 90);
        assert_eq!(u16::from(CertType::URI), 253);
        assert_eq!(u16::from(CertType::OID), 254);
        assert_eq!(u16::from(cert_type_experimental_80), 65280);
        assert_eq!(u16::from(cert_type_experimental_90), 65290);
    }

    #[test]
    fn test_algorithm() {
        assert_eq!(Algorithm::Reserved(0), Algorithm::from(0));
        assert_eq!(Algorithm::DH, Algorithm::from(2));
        assert_eq!(Algorithm::DSA, Algorithm::from(3));
        assert_eq!(Algorithm::ECC, Algorithm::from(4));
        assert_eq!(Algorithm::RSASHA1, Algorithm::from(5));
        assert_eq!(Algorithm::DSANSEC3SHA1, Algorithm::from(6));
        assert_eq!(Algorithm::RSASHA1NSEC3SHA1, Algorithm::from(7));
        assert_eq!(Algorithm::RSASHA256, Algorithm::from(8));
        assert_eq!(Algorithm::Reserved(9), Algorithm::from(9));
        assert_eq!(Algorithm::RSASHA512, Algorithm::from(10));
        assert_eq!(Algorithm::Reserved(11), Algorithm::from(11));
        assert_eq!(Algorithm::ECCGOST, Algorithm::from(12));
        assert_eq!(Algorithm::ECDSAP256SHA256, Algorithm::from(13));
        assert_eq!(Algorithm::ECDSAP384SHA384, Algorithm::from(14));
        assert_eq!(Algorithm::ED25519, Algorithm::from(15));
        assert_eq!(Algorithm::ED448, Algorithm::from(16));
        assert_eq!(Algorithm::SM2SM3, Algorithm::from(17));
        assert_eq!(Algorithm::Unassigned(18), Algorithm::from(18));
        assert_eq!(Algorithm::Unassigned(20), Algorithm::from(20));
        assert_eq!(Algorithm::ECCGOST12, Algorithm::from(23));
        assert_eq!(Algorithm::INDIRECT, Algorithm::from(252));
        assert_eq!(Algorithm::PRIVATEDNS, Algorithm::from(253));
        assert_eq!(Algorithm::PRIVATEOID, Algorithm::from(254));

        let algorithm_reserved_0 = Algorithm::Reserved(0);
        let algorithm_reserved_9 = Algorithm::Reserved(9);

        assert_eq!(u8::from(algorithm_reserved_0), 0);
        assert_eq!(u8::from(Algorithm::DH), 2);

        assert_eq!(u8::from(Algorithm::DSA), 3);
        assert_eq!(u8::from(Algorithm::ECC), 4);
        assert_eq!(u8::from(Algorithm::RSASHA1), 5);
        assert_eq!(u8::from(Algorithm::DSANSEC3SHA1), 6);
        assert_eq!(u8::from(Algorithm::RSASHA1NSEC3SHA1), 7);
        assert_eq!(u8::from(Algorithm::RSASHA256), 8);
        assert_eq!(u8::from(Algorithm::Reserved(9)), 9);
        assert_eq!(u8::from(Algorithm::RSASHA512), 10);
        assert_eq!(u8::from(Algorithm::Reserved(11)), 11);
        assert_eq!(u8::from(Algorithm::ECCGOST), 12);
        assert_eq!(u8::from(Algorithm::ECDSAP256SHA256), 13);
        assert_eq!(u8::from(Algorithm::ECDSAP384SHA384), 14);
        assert_eq!(u8::from(Algorithm::ED25519), 15);
        assert_eq!(u8::from(Algorithm::ED448), 16);
        assert_eq!(u8::from(Algorithm::SM2SM3), 17);
        assert_eq!(u8::from(Algorithm::Unassigned(18)), 18);
        assert_eq!(u8::from(Algorithm::Unassigned(20)), 20);
        assert_eq!(u8::from(Algorithm::ECCGOST12), 23);
        assert_eq!(u8::from(Algorithm::INDIRECT), 252);
        assert_eq!(u8::from(Algorithm::PRIVATEDNS), 253);
        assert_eq!(u8::from(Algorithm::PRIVATEOID), 254);

        assert_eq!(u8::from(algorithm_reserved_9), 9);
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
            result.is_err(),
            "Expected error due to invalid cert_record length"
        );

        if let Err(e) = result {
            assert_eq!(e.to_string(), "invalid cert_record length".to_string());
        }
    }
}
