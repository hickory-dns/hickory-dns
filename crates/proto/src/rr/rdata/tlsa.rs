// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLSA records for storing TLS certificate validation information
#![allow(clippy::use_self)]

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use super::sshfp;

use crate::error::*;
use crate::serialize::binary::*;

/// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2.1)
///
/// ```text
/// 2.1.  TLSA RDATA Wire Format
///
///    The RDATA for a TLSA RR consists of a one-octet certificate usage
///    field, a one-octet selector field, a one-octet matching type field,
///    and the certificate association data field.
///
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |  Cert. Usage  |   Selector    | Matching Type |               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
///    /                                                               /
///    /                 Certificate Association Data                  /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TLSA {
    cert_usage: CertUsage,
    selector: Selector,
    matching: Matching,
    cert_data: Vec<u8>,
}

/// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2.1.1)
///
/// ```text
/// 2.1.1.  The Certificate Usage Field
///
///    A one-octet value, called "certificate usage", specifies the provided
///    association that will be used to match the certificate presented in
///    the TLS handshake.  This value is defined in a new IANA registry (see
///    Section 7.2) in order to make it easier to add additional certificate
///    usages in the future.  The certificate usages defined in this
///    document are:
///
///       0 -- CA
///
///       1 -- Service
///
///       2 -- TrustAnchor
///
///       3 -- DomainIssued
///
///    The certificate usages defined in this document explicitly only apply
///    to PKIX-formatted certificates in DER encoding [X.690].  If TLS
///    allows other formats later, or if extensions to this RRtype are made
///    that accept other formats for certificates, those certificates will
///    need their own certificate usage values.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CertUsage {
    /// ```text
    ///       0 -- Certificate usage 0 is used to specify a CA certificate, or
    ///       the public key of such a certificate, that MUST be found in any of
    ///       the PKIX certification paths for the end entity certificate given
    ///       by the server in TLS.  This certificate usage is sometimes
    ///       referred to as "CA constraint" because it limits which CA can be
    ///       used to issue certificates for a given service on a host.  The
    ///       presented certificate MUST pass PKIX certification path
    ///       validation, and a CA certificate that matches the TLSA record MUST
    ///       be included as part of a valid certification path.  Because this
    ///       certificate usage allows both trust anchors and CA certificates,
    ///       the certificate might or might not have the basicConstraints
    ///       extension present.
    /// ```
    CA,

    /// ```text
    ///       1 -- Certificate usage 1 is used to specify an end entity
    ///       certificate, or the public key of such a certificate, that MUST be
    ///       matched with the end entity certificate given by the server in
    ///       TLS.  This certificate usage is sometimes referred to as "service
    ///       certificate constraint" because it limits which end entity
    ///       certificate can be used by a given service on a host.  The target
    ///       certificate MUST pass PKIX certification path validation and MUST
    ///       match the TLSA record.
    /// ```
    Service,

    /// ```text
    ///       2 -- Certificate usage 2 is used to specify a certificate, or the
    ///       public key of such a certificate, that MUST be used as the trust
    ///       anchor when validating the end entity certificate given by the
    ///       server in TLS.  This certificate usage is sometimes referred to as
    ///       "trust anchor assertion" and allows a domain name administrator to
    ///       specify a new trust anchor -- for example, if the domain issues
    ///       its own certificates under its own CA that is not expected to be
    ///       in the end users' collection of trust anchors.  The target
    ///       certificate MUST pass PKIX certification path validation, with any
    ///       certificate matching the TLSA record considered to be a trust
    ///       anchor for this certification path validation.
    /// ```
    TrustAnchor,

    /// ```text
    ///       3 -- Certificate usage 3 is used to specify a certificate, or the
    ///       public key of such a certificate, that MUST match the end entity
    ///       certificate given by the server in TLS.  This certificate usage is
    ///       sometimes referred to as "domain-issued certificate" because it
    ///       allows for a domain name administrator to issue certificates for a
    ///       domain without involving a third-party CA.  The target certificate
    ///       MUST match the TLSA record.  The difference between certificate
    ///       usage 1 and certificate usage 3 is that certificate usage 1
    ///       requires that the certificate pass PKIX validation, but PKIX
    ///       validation is not tested for certificate usage 3.
    /// ```
    DomainIssued,

    /// Unassigned at the time of this implementation
    Unassigned(u8),

    /// Private usage
    Private,
}

impl From<u8> for CertUsage {
    fn from(usage: u8) -> Self {
        match usage {
            0 => Self::CA,
            1 => Self::Service,
            2 => Self::TrustAnchor,
            3 => Self::DomainIssued,
            4..=254 => Self::Unassigned(usage),
            255 => Self::Private,
        }
    }
}

impl From<CertUsage> for u8 {
    fn from(usage: CertUsage) -> Self {
        match usage {
            CertUsage::CA => 0,
            CertUsage::Service => 1,
            CertUsage::TrustAnchor => 2,
            CertUsage::DomainIssued => 3,
            CertUsage::Unassigned(usage) => usage,
            CertUsage::Private => 255,
        }
    }
}

/// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2.1.1)
///
/// ```text
/// 2.1.2.  The Selector Field
///
///    A one-octet value, called "selector", specifies which part of the TLS
///    certificate presented by the server will be matched against the
///    association data.  This value is defined in a new IANA registry (see
///    Section 7.3).  The selectors defined in this document are:
///
///       0 -- Full
///
///       1 -- Spki
///
///    (Note that the use of "selector" in this document is completely
///    unrelated to the use of "selector" in DomainKeys Identified Mail
///    (DKIM) [RFC6376].)
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Selector {
    /// Full certificate: the Certificate binary structure as defined in [RFC5280](https://tools.ietf.org/html/rfc5280)
    Full,

    /// SubjectPublicKeyInfo: DER-encoded binary structure as defined in [RFC5280](https://tools.ietf.org/html/rfc5280)
    Spki,

    /// Unassigned at the time of this writing
    Unassigned(u8),

    /// Private usage
    Private,
}

impl From<u8> for Selector {
    fn from(selector: u8) -> Self {
        match selector {
            0 => Self::Full,
            1 => Self::Spki,
            2..=254 => Self::Unassigned(selector),
            255 => Self::Private,
        }
    }
}

impl From<Selector> for u8 {
    fn from(selector: Selector) -> Self {
        match selector {
            Selector::Full => 0,
            Selector::Spki => 1,
            Selector::Unassigned(selector) => selector,
            Selector::Private => 255,
        }
    }
}

/// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2.1.3)
///
/// ```text
/// 2.1.3.  The Matching Type Field
///
///    A one-octet value, called "matching type", specifies how the
///    certificate association is presented.  This value is defined in a new
///    IANA registry (see Section 7.4).  The types defined in this document
///    are:
///
///       0 -- Raw
///
///       1 -- Sha256
///
///       2 -- Sha512
///
///    If the TLSA record's matching type is a hash, having the record use
///    the same hash algorithm that was used in the signature in the
///    certificate (if possible) will assist clients that support a small
///    number of hash algorithms.
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Matching {
    /// Exact match on selected content
    Raw,

    /// SHA-256 hash of selected content [RFC6234](https://tools.ietf.org/html/rfc6234)
    Sha256,

    /// SHA-512 hash of selected content [RFC6234](https://tools.ietf.org/html/rfc6234)
    Sha512,

    /// Unassigned at the time of this writing
    Unassigned(u8),

    /// Private usage
    Private,
}

impl From<u8> for Matching {
    fn from(matching: u8) -> Self {
        match matching {
            0 => Self::Raw,
            1 => Self::Sha256,
            2 => Self::Sha512,
            3..=254 => Self::Unassigned(matching),
            255 => Self::Private,
        }
    }
}

impl From<Matching> for u8 {
    fn from(matching: Matching) -> Self {
        match matching {
            Matching::Raw => 0,
            Matching::Sha256 => 1,
            Matching::Sha512 => 2,
            Matching::Unassigned(matching) => matching,
            Matching::Private => 255,
        }
    }
}

impl TLSA {
    /// Constructs a new TLSA
    ///
    /// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2)
    ///
    /// ```text
    /// 2.  The TLSA Resource Record
    ///
    ///    The TLSA DNS resource record (RR) is used to associate a TLS server
    ///    certificate or public key with the domain name where the record is
    ///    found, thus forming a "TLSA certificate association".  The semantics
    ///    of how the TLSA RR is interpreted are given later in this document.
    ///
    ///    The type value for the TLSA RR type is defined in Section 7.1.
    ///
    ///    The TLSA RR is class independent.
    ///
    ///    The TLSA RR has no special Time to Live (TTL) requirements.
    /// ```
    pub fn new(
        cert_usage: CertUsage,
        selector: Selector,
        matching: Matching,
        cert_data: Vec<u8>,
    ) -> Self {
        Self {
            cert_usage,
            selector,
            matching,
            cert_data,
        }
    }

    /// Specifies the provided association that will be used to match the certificate presented in the TLS handshake
    pub fn cert_usage(&self) -> CertUsage {
        self.cert_usage
    }

    /// Specifies which part of the TLS certificate presented by the server will be matched against the association data
    pub fn selector(&self) -> Selector {
        self.selector
    }

    /// Specifies how the certificate association is presented
    pub fn matching(&self) -> Matching {
        self.matching
    }

    /// Binary data for validating the cert, see other members to understand format
    pub fn cert_data(&self) -> &[u8] {
        &self.cert_data
    }
}

/// Read the RData from the given Decoder
///
/// ```text
///                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |  Cert. Usage  |   Selector    | Matching Type |               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
///    /                                                               /
///    /                 Certificate Association Data                  /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<TLSA> {
    let cert_usage = decoder.read_u8()?.unverified(/*CertUsage is verified*/).into();
    let selector = decoder.read_u8()?.unverified(/*Selector is verified*/).into();
    let matching = decoder.read_u8()?.unverified(/*Matching is verified*/).into();

    // the remaining data is for the cert
    let cert_len = rdata_length
        .map(|u| u as usize)
        .checked_sub(3)
        .map_err(|_| ProtoError::from("invalid rdata length in TLSA"))?
        .unverified(/*used purely as length safely*/);
    let cert_data = decoder.read_vec(cert_len)?.unverified(/*will fail in usage if invalid*/);

    Ok(TLSA {
        cert_usage,
        selector,
        matching,
        cert_data,
    })
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, tlsa: &TLSA) -> ProtoResult<()> {
    encoder.emit_u8(tlsa.cert_usage.into())?;
    encoder.emit_u8(tlsa.selector.into())?;
    encoder.emit_u8(tlsa.matching.into())?;
    encoder.emit_vec(&tlsa.cert_data)?;
    Ok(())
}

/// [RFC 6698, DNS-Based Authentication for TLS](https://tools.ietf.org/html/rfc6698#section-2.2)
///
/// ```text
/// 2.2.  TLSA RR Presentation Format
///
///   The presentation format of the RDATA portion (as defined in
///   [RFC1035]) is as follows:
///
///   o  The certificate usage field MUST be represented as an 8-bit
///      unsigned integer.
///
///   o  The selector field MUST be represented as an 8-bit unsigned
///      integer.
///
///   o  The matching type field MUST be represented as an 8-bit unsigned
///      integer.
///
///   o  The certificate association data field MUST be represented as a
///      string of hexadecimal characters.  Whitespace is allowed within
///      the string of hexadecimal characters, as described in [RFC1035].
///
/// 2.3.  TLSA RR Examples
///
///    In the following examples, the domain name is formed using the rules
///    in Section 3.
///
///    An example of a hashed (SHA-256) association of a PKIX CA
///    certificate:
///
///    _443._tcp.www.example.com. IN TLSA (
///       0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
///             7983a1d16e8a410e4561cb106618e971 )
///
///    An example of a hashed (SHA-512) subject public key association of a
///    PKIX end entity certificate:
///
///    _443._tcp.www.example.com. IN TLSA (
///       1 1 2 92003ba34942dc74152e2f2c408d29ec
///             a5a520e7f2e06bb944f4dca346baf63c
///             1b177615d466f6c4b71c216a50292bd5
///             8c9ebdd2f74e38fe51ffd48c43326cbc )
///
///    An example of a full certificate association of a PKIX end entity
///    certificate:
///
///    _443._tcp.www.example.com. IN TLSA (
///       3 0 0 30820307308201efa003020102020... )
/// ```
impl fmt::Display for TLSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{usage} {selector} {matching} {cert}",
            usage = u8::from(self.cert_usage),
            selector = u8::from(self.selector),
            matching = u8::from(self.matching),
            cert = sshfp::HEX.encode(&self.cert_data),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn read_cert_usage() {
        assert_eq!(CertUsage::CA, CertUsage::from(0));
        assert_eq!(CertUsage::Service, CertUsage::from(1));
        assert_eq!(CertUsage::TrustAnchor, CertUsage::from(2));
        assert_eq!(CertUsage::DomainIssued, CertUsage::from(3));
        assert_eq!(CertUsage::Unassigned(4), CertUsage::from(4));
        assert_eq!(CertUsage::Unassigned(254), CertUsage::from(254));
        assert_eq!(CertUsage::Private, CertUsage::from(255));

        assert_eq!(u8::from(CertUsage::CA), 0);
        assert_eq!(u8::from(CertUsage::Service), 1);
        assert_eq!(u8::from(CertUsage::TrustAnchor), 2);
        assert_eq!(u8::from(CertUsage::DomainIssued), 3);
        assert_eq!(u8::from(CertUsage::Unassigned(4)), 4);
        assert_eq!(u8::from(CertUsage::Unassigned(254)), 254);
        assert_eq!(u8::from(CertUsage::Private), 255);
    }

    #[test]
    fn read_selector() {
        assert_eq!(Selector::Full, Selector::from(0));
        assert_eq!(Selector::Spki, Selector::from(1));
        assert_eq!(Selector::Unassigned(2), Selector::from(2));
        assert_eq!(Selector::Unassigned(254), Selector::from(254));
        assert_eq!(Selector::Private, Selector::from(255));

        assert_eq!(u8::from(Selector::Full), 0);
        assert_eq!(u8::from(Selector::Spki), 1);
        assert_eq!(u8::from(Selector::Unassigned(2)), 2);
        assert_eq!(u8::from(Selector::Unassigned(254)), 254);
        assert_eq!(u8::from(Selector::Private), 255);
    }

    #[test]
    fn read_matching() {
        assert_eq!(Matching::Raw, Matching::from(0));
        assert_eq!(Matching::Sha256, Matching::from(1));
        assert_eq!(Matching::Sha512, Matching::from(2));
        assert_eq!(Matching::Unassigned(3), Matching::from(3));
        assert_eq!(Matching::Unassigned(254), Matching::from(254));
        assert_eq!(Matching::Private, Matching::from(255));

        assert_eq!(u8::from(Matching::Raw), 0);
        assert_eq!(u8::from(Matching::Sha256), 1);
        assert_eq!(u8::from(Matching::Sha512), 2);
        assert_eq!(u8::from(Matching::Unassigned(3)), 3);
        assert_eq!(u8::from(Matching::Unassigned(254)), 254);
        assert_eq!(u8::from(Matching::Private), 255);
    }

    fn test_encode_decode(rdata: TLSA) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        emit(&mut encoder, &rdata).expect("failed to emit tlsa");
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata =
            read(&mut decoder, Restrict::new(bytes.len() as u16)).expect("failed to read back");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_encode_decode_tlsa() {
        test_encode_decode(TLSA::new(
            CertUsage::Service,
            Selector::Spki,
            Matching::Sha256,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ));
        test_encode_decode(TLSA::new(
            CertUsage::CA,
            Selector::Full,
            Matching::Raw,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ));
        test_encode_decode(TLSA::new(
            CertUsage::DomainIssued,
            Selector::Full,
            Matching::Sha512,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ));
        test_encode_decode(TLSA::new(
            CertUsage::Unassigned(40),
            Selector::Unassigned(39),
            Matching::Unassigned(6),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ));
    }
}
