// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! record type definitions

use std::cmp::Ordering;
use std::convert::From;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::serialize::binary::*;

// TODO: adopt proper restrictions on usage: https://tools.ietf.org/html/rfc6895 section 3.1
//  add the data TYPEs, QTYPEs, and Meta-TYPEs
//

/// The type of the resource record.
///
/// This specifies the type of data in the RData field of the Resource Record
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
#[non_exhaustive]
pub enum RecordType {
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) IPv4 Address record
    A,
    /// [RFC 3596](https://tools.ietf.org/html/rfc3596) IPv6 address record
    AAAA,
    /// [ANAME draft-ietf-dnsop-aname](https://tools.ietf.org/html/draft-ietf-dnsop-aname-04)
    ANAME,
    //  AFSDB,      //	18	RFC 1183	AFS database record
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) All cached records, aka ANY
    ANY,
    //  APL,        //	42	RFC 3123	Address Prefix List
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Authoritative Zone Transfer
    AXFR,
    /// [RFC 6844](https://tools.ietf.org/html/rfc6844) Certification Authority Authorization
    CAA,
    /// [RFC 7344](https://tools.ietf.org/html/rfc7344) Child DS
    CDS,
    /// [RFC 7344](https://tools.ietf.org/html/rfc7344) Child DNSKEY
    CDNSKEY,
    //  CERT,       // 37 RFC 4398 Certificate record
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Canonical name record
    CNAME,
    //  DHCID,      // 49 RFC 4701 DHCP identifier
    //  DLV,        //	32769	RFC 4431	DNSSEC Lookaside Validation record
    //  DNAME,      // 39 RFC 2672 Delegation Name
    /// [RFC 7477](https://tools.ietf.org/html/rfc4034) Child-to-parent synchronization record
    CSYNC,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) DNS Key record: RSASHA256 and RSASHA512, RFC5702
    DNSKEY,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) Delegation signer: RSASHA256 and RSASHA512, RFC5702
    DS,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) host information
    HINFO,
    //  HIP,        // 55 RFC 5205 Host Identity Protocol
    /// [RFC draft-ietf-dnsop-svcb-https-03](https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-03) DNS SVCB and HTTPS RRs
    HTTPS,
    //  IPSECKEY,   // 45 RFC 4025 IPsec Key
    /// [RFC 1996](https://tools.ietf.org/html/rfc1996) Incremental Zone Transfer
    IXFR,
    //  KX,         // 36 RFC 2230 Key eXchanger record
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535) and [RFC 2930](https://tools.ietf.org/html/rfc2930) Key record
    KEY,
    //  LOC,        // 29 RFC 1876 Location record
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail exchange record
    MX,
    /// [RFC 3403](https://tools.ietf.org/html/rfc3403) Naming Authority Pointer
    NAPTR,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Name server record
    NS,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) Next-Secure record
    NSEC,
    /// [RFC 5155](https://tools.ietf.org/html/rfc5155) NSEC record version 3
    NSEC3,
    /// [RFC 5155](https://tools.ietf.org/html/rfc5155) NSEC3 parameters
    NSEC3PARAM,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Null server record, for testing
    NULL,
    /// [RFC 7929](https://tools.ietf.org/html/rfc7929) OpenPGP public key
    OPENPGPKEY,
    /// [RFC 6891](https://tools.ietf.org/html/rfc6891) Option
    OPT,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Pointer record
    PTR,
    //  RP,         // 17 RFC 1183 Responsible person
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) DNSSEC signature: RSASHA256 and RSASHA512, RFC5702
    RRSIG,
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535) (and [RFC 2931](https://tools.ietf.org/html/rfc2931)) Signature, to support [RFC 2137](https://tools.ietf.org/html/rfc2137) Update.
    SIG,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) and [RFC 2308](https://tools.ietf.org/html/rfc2308) Start of [a zone of] authority record
    SOA,
    /// [RFC 2782](https://tools.ietf.org/html/rfc2782) Service locator
    SRV,
    /// [RFC 4255](https://tools.ietf.org/html/rfc4255) SSH Public Key Fingerprint
    SSHFP,
    /// [RFC draft-ietf-dnsop-svcb-https-03](https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-03) DNS SVCB and HTTPS RRs
    SVCB,
    //  TA,         // 32768 N/A DNSSEC Trust Authorities
    //  TKEY,       // 249 RFC 2930 Secret key record
    /// [RFC 6698](https://tools.ietf.org/html/rfc6698) TLSA certificate association
    TLSA,
    /// [RFC 8945](https://tools.ietf.org/html/rfc8945) Transaction Signature
    TSIG,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Text record
    TXT,
    /// Unknown Record type, or unsupported
    Unknown(u16),

    /// This corresponds to a record type of 0, unspecified
    ZERO,
}

impl RecordType {
    /// Returns true if this is an ANY
    #[inline]
    pub fn is_any(self) -> bool {
        self == RecordType::ANY
    }

    /// Returns true if this is a CNAME
    #[inline]
    pub fn is_cname(self) -> bool {
        self == RecordType::CNAME
    }

    /// Returns true if this is an NS
    #[inline]
    pub fn is_ns(self) -> bool {
        self == RecordType::NS
    }

    /// Returns true if this is an SOA
    #[inline]
    pub fn is_soa(self) -> bool {
        self == RecordType::SOA
    }

    /// Returns true if this is an SRV
    #[inline]
    pub fn is_srv(self) -> bool {
        self == RecordType::SRV
    }

    /// Returns true if this is an A or an AAAA record
    #[inline]
    pub fn is_ip_addr(self) -> bool {
        matches!(self, RecordType::A | RecordType::AAAA)
    }

    /// Returns true if this is a DNSSEC RecordType
    #[inline]
    pub fn is_dnssec(self) -> bool {
        matches!(
            self,
            RecordType::DNSKEY
                | RecordType::CDNSKEY
                | RecordType::CDS
                | RecordType::DS
                | RecordType::KEY
                | RecordType::NSEC
                | RecordType::NSEC3
                | RecordType::NSEC3PARAM
                | RecordType::RRSIG
                | RecordType::SIG
                | RecordType::TSIG
        )
    }
}

impl FromStr for RecordType {
    type Err = ProtoError;

    /// Convert `&str` to `RecordType`
    ///
    /// ```
    /// use std::str::FromStr;
    /// use trust_dns_proto::rr::record_type::RecordType;
    ///
    /// let var: RecordType = RecordType::from_str("A").unwrap();
    /// assert_eq!(RecordType::A, var);
    /// ```
    fn from_str(str: &str) -> ProtoResult<Self> {
        // TODO missing stuff?
        debug_assert!(str.chars().all(|x| char::is_digit(x, 36)));
        match str {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "ANAME" => Ok(RecordType::ANAME),
            "AXFR" => Ok(RecordType::AXFR),
            "CAA" => Ok(RecordType::CAA),
            "CDNSKEY" => Ok(RecordType::CDNSKEY),
            "CDS" => Ok(RecordType::CDS),
            "CNAME" => Ok(RecordType::CNAME),
            "CSYNC" => Ok(RecordType::CSYNC),
            "DNSKEY" => Ok(RecordType::DNSKEY),
            "DS" => Ok(RecordType::DS),
            "HINFO" => Ok(RecordType::HINFO),
            "HTTPS" => Ok(RecordType::HTTPS),
            "KEY" => Ok(RecordType::KEY),
            "MX" => Ok(RecordType::MX),
            "NAPTR" => Ok(RecordType::NAPTR),
            "NSEC" => Ok(RecordType::NSEC),
            "NSEC3" => Ok(RecordType::NSEC3),
            "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
            "NS" => Ok(RecordType::NS),
            "NULL" => Ok(RecordType::NULL),
            "OPENPGPKEY" => Ok(RecordType::OPENPGPKEY),
            "PTR" => Ok(RecordType::PTR),
            "RRSIG" => Ok(RecordType::RRSIG),
            "SIG" => Ok(RecordType::SIG),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "SSHFP" => Ok(RecordType::SSHFP),
            "SVCB" => Ok(RecordType::SVCB),
            "TLSA" => Ok(RecordType::TLSA),
            "TXT" => Ok(RecordType::TXT),
            "TSIG" => Ok(RecordType::TSIG),
            "ANY" | "*" => Ok(RecordType::ANY),
            _ => Err(ProtoErrorKind::UnknownRecordTypeStr(str.to_string()).into()),
        }
    }
}

impl From<u16> for RecordType {
    /// Convert from `u16` to `RecordType`
    ///
    /// ```
    /// use trust_dns_proto::rr::record_type::RecordType;
    ///
    /// let var = RecordType::from(1);
    /// assert_eq!(RecordType::A, var);
    /// ```
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            // TODO: wrong value here, see https://github.com/bluejekyll/trust-dns/issues/723
            65305 => RecordType::ANAME,
            255 => RecordType::ANY,
            251 => RecordType::IXFR,
            252 => RecordType::AXFR,
            257 => RecordType::CAA,
            59 => RecordType::CDS,
            60 => RecordType::CDNSKEY,
            5 => RecordType::CNAME,
            62 => RecordType::CSYNC,
            48 => RecordType::DNSKEY,
            43 => RecordType::DS,
            13 => RecordType::HINFO,
            65 => RecordType::HTTPS,
            25 => RecordType::KEY,
            15 => RecordType::MX,
            35 => RecordType::NAPTR,
            2 => RecordType::NS,
            47 => RecordType::NSEC,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            10 => RecordType::NULL,
            61 => RecordType::OPENPGPKEY,
            41 => RecordType::OPT,
            12 => RecordType::PTR,
            46 => RecordType::RRSIG,
            24 => RecordType::SIG,
            6 => RecordType::SOA,
            33 => RecordType::SRV,
            44 => RecordType::SSHFP,
            64 => RecordType::SVCB,
            52 => RecordType::TLSA,
            250 => RecordType::TSIG,
            16 => RecordType::TXT,
            0 => RecordType::ZERO,
            // all unknown record types
            _ => RecordType::Unknown(value),
        }
    }
}

impl BinEncodable for RecordType {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16((*self).into())
    }
}

impl<'r> BinDecodable<'r> for RecordType {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        Ok(decoder
            .read_u16()
            .map(
                Restrict::unverified, /*RecordType is safe with any u16*/
            )
            .map(Self::from)?)
    }
}

// TODO make these a macro...

/// Convert from `RecordType` to `&str`
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::rr::record_type::RecordType;
///
/// let var: &'static str = From::from(RecordType::A);
/// assert_eq!("A", var);
///
/// let var: &'static str = RecordType::A.into();
/// assert_eq!("A", var);
/// ```
impl From<RecordType> for &'static str {
    fn from(rt: RecordType) -> &'static str {
        match rt {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::ANAME => "ANAME",
            RecordType::ANY => "ANY",
            RecordType::AXFR => "AXFR",
            RecordType::CAA => "CAA",
            RecordType::CDNSKEY => "CDNSKEY",
            RecordType::CDS => "CDS",
            RecordType::CNAME => "CNAME",
            RecordType::CSYNC => "CSYNC",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::DS => "DS",
            RecordType::HINFO => "HINFO",
            RecordType::HTTPS => "HTTPS",
            RecordType::KEY => "KEY",
            RecordType::IXFR => "IXFR",
            RecordType::MX => "MX",
            RecordType::NAPTR => "NAPTR",
            RecordType::NS => "NS",
            RecordType::NSEC => "NSEC",
            RecordType::NSEC3 => "NSEC3",
            RecordType::NSEC3PARAM => "NSEC3PARAM",
            RecordType::NULL => "NULL",
            RecordType::OPENPGPKEY => "OPENPGPKEY",
            RecordType::OPT => "OPT",
            RecordType::PTR => "PTR",
            RecordType::RRSIG => "RRSIG",
            RecordType::SIG => "SIG",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::SSHFP => "SSHFP",
            RecordType::SVCB => "SVCB",
            RecordType::TLSA => "TLSA",
            RecordType::TSIG => "TSIG",
            RecordType::TXT => "TXT",
            RecordType::ZERO => "ZERO",
            RecordType::Unknown(_) => "Unknown",
        }
    }
}

/// Convert from `RecordType` to `u16`
///
/// ```
/// use std::convert::From;
/// use trust_dns_proto::rr::record_type::RecordType;
///
/// let var: u16 = RecordType::A.into();
/// assert_eq!(1, var);
/// ```
impl From<RecordType> for u16 {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            // TODO: wrong value here, see https://github.com/bluejekyll/trust-dns/issues/723
            RecordType::ANAME => 65305,
            RecordType::ANY => 255,
            RecordType::AXFR => 252,
            RecordType::CAA => 257,
            RecordType::CDNSKEY => 60,
            RecordType::CDS => 59,
            RecordType::CNAME => 5,
            RecordType::CSYNC => 62,
            RecordType::DNSKEY => 48,
            RecordType::DS => 43,
            RecordType::HINFO => 13,
            RecordType::HTTPS => 65,
            RecordType::KEY => 25,
            RecordType::IXFR => 251,
            RecordType::MX => 15,
            RecordType::NAPTR => 35,
            RecordType::NS => 2,
            RecordType::NSEC => 47,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::NULL => 10,
            RecordType::OPENPGPKEY => 61,
            RecordType::OPT => 41,
            RecordType::PTR => 12,
            RecordType::RRSIG => 46,
            RecordType::SIG => 24,
            RecordType::SOA => 6,
            RecordType::SRV => 33,
            RecordType::SSHFP => 44,
            RecordType::SVCB => 64,
            RecordType::TLSA => 52,
            RecordType::TSIG => 250,
            RecordType::TXT => 16,
            RecordType::ZERO => 0,
            RecordType::Unknown(code) => code,
        }
    }
}

/// [Canonical DNS Name Order](https://tools.ietf.org/html/rfc4034#section-6)
impl PartialOrd<RecordType> for RecordType {
    fn partial_cmp(&self, other: &RecordType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// [Canonical DNS Name Order](https://tools.ietf.org/html/rfc4034#section-6)
impl Ord for RecordType {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(Into::<&str>::into(*self))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test_order() {
        let ordered = vec![
            RecordType::A,
            RecordType::NS,
            RecordType::CNAME,
            RecordType::SOA,
            RecordType::NULL,
            RecordType::PTR,
            RecordType::HINFO,
            RecordType::MX,
            RecordType::TXT,
            RecordType::AAAA,
            RecordType::SRV,
            RecordType::CSYNC,
            RecordType::AXFR,
            RecordType::ANY,
        ];

        let mut unordered = vec![
            RecordType::ANY,
            RecordType::NULL,
            RecordType::AXFR,
            RecordType::A,
            RecordType::NS,
            RecordType::SOA,
            RecordType::SRV,
            RecordType::PTR,
            RecordType::MX,
            RecordType::CNAME,
            RecordType::TXT,
            RecordType::AAAA,
            RecordType::HINFO,
            RecordType::CSYNC,
        ];

        unordered.sort();

        for rtype in unordered.clone() {
            println!("u16 for {:?}: {}", rtype, u16::from(rtype));
        }

        assert_eq!(ordered, unordered);
    }

    /// Check that all record type names parse into unique `RecordType` instances,
    /// and can be converted back into the same name.
    #[test]
    fn test_record_type_parse() {
        let record_names = &[
            "A",
            "AAAA",
            "ANAME",
            "CAA",
            "CNAME",
            "CSYNC",
            "HINFO",
            "NULL",
            "MX",
            "NAPTR",
            "NS",
            "OPENPGPKEY",
            "PTR",
            "SOA",
            "SRV",
            "SSHFP",
            "TLSA",
            "TXT",
            "ANY",
            "AXFR",
        ];

        #[cfg(feature = "dnssec")]
        let dnssec_record_names = &[
            "CDNSKEY",
            "CDS",
            "DNSKEY",
            "DS",
            "KEY",
            "NSEC",
            "NSEC3",
            "NSEC3PARAM",
            "RRSIG",
            "SIG",
            "TSIG",
        ];
        #[cfg(not(feature = "dnssec"))]
        let dnssec_record_names = &[];

        let mut rtypes = std::collections::HashSet::new();
        for name in record_names.iter().chain(dnssec_record_names) {
            let rtype: RecordType = name.parse().unwrap();
            assert_eq!(rtype.to_string().to_ascii_uppercase().as_str(), *name);
            assert!(rtypes.insert(rtype));
        }
    }
}
