// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! allows a DNS domain name holder to specify one or more Certification
//! Authorities (CAs) authorized to issue certificates for that domain.
//!
//! [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844)
//!
//! ```text
//! The Certification Authority Authorization (CAA) DNS Resource Record
//! allows a DNS domain name holder to specify one or more Certification
//! Authorities (CAs) authorized to issue certificates for that domain.
//! CAA Resource Records allow a public Certification Authority to
//! implement additional controls to reduce the risk of unintended
//! certificate mis-issue.  This document defines the syntax of the CAA
//! record and rules for processing CAA records by certificate issuers.
//! ```

use error::*;
use rr::domain::Name;
use serialize::binary::*;

/// The CAA RR Type
///
/// [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844#section-3)
///
/// ```text
/// 3.  The CAA RR Type
///
/// A CAA RR consists of a flags byte and a tag-value pair referred to as
/// a property.  Multiple properties MAY be associated with the same
/// domain name by publishing multiple CAA RRs at that domain name.  The
/// following flag is defined:
///
/// Issuer Critical:  If set to '1', indicates that the corresponding
///    property tag MUST be understood if the semantics of the CAA record
///    are to be correctly interpreted by an issuer.
///
///    Issuers MUST NOT issue certificates for a domain if the relevant
///    CAA Resource Record set contains unknown property tags that have
///    the Critical bit set.
///
/// The following property tags are defined:
///
/// issue <Issuer Domain Name> [; <name>=<value> ]* :  The issue property
///    entry authorizes the holder of the domain name <Issuer Domain
///    Name> or a party acting under the explicit authority of the holder
///    of that domain name to issue certificates for the domain in which
///    the property is published.
///
/// issuewild <Issuer Domain Name> [; <name>=<value> ]* :  The issuewild
///    property entry authorizes the holder of the domain name <Issuer
///    Domain Name> or a party acting under the explicit authority of the
///    holder of that domain name to issue wildcard certificates for the
///    domain in which the property is published.
///
/// iodef <URL> :  Specifies a URL to which an issuer MAY report
///    certificate issue requests that are inconsistent with the issuer's
///    Certification Practices or Certificate Policy, or that a
///    Certificate Evaluator may use to report observation of a possible
///    policy violation.  The Incident Object Description Exchange Format
///    (IODEF) format is used [RFC5070].
///
/// The following example is a DNS zone file (see [RFC1035]) that informs
/// CAs that certificates are not to be issued except by the holder of
/// the domain name 'ca.example.net' or an authorized agent thereof.
/// This policy applies to all subordinate domains under example.com.
///
/// $ORIGIN example.com
/// .       CAA 0 issue "ca.example.net"
///
/// If the domain name holder specifies one or more iodef properties, a
/// certificate issuer MAY report invalid certificate requests to that
/// address.  In the following example, the domain name holder specifies
/// that reports may be made by means of email with the IODEF data as an
/// attachment, a Web service [RFC6546], or both:
///
/// $ORIGIN example.com
/// .       CAA 0 issue "ca.example.net"
/// .       CAA 0 iodef "mailto:security@example.com"
/// .       CAA 0 iodef "http://iodef.example.com/"
///
/// A certificate issuer MAY specify additional parameters that allow
/// customers to specify additional parameters governing certificate
/// issuance.  This might be the Certificate Policy under which the
/// certificate is to be issued, the authentication process to be used
/// might be specified, or an account number specified by the CA to
/// enable these parameters to be retrieved.
///
/// For example, the CA 'ca.example.net' has requested its customer
/// 'example.com' to specify the CA's account number '230123' in each of
/// the customer's CAA records.
///
/// $ORIGIN example.com
/// .       CAA 0 issue "ca.example.net; account=230123"
///
/// The syntax of additional parameters is a sequence of name-value pairs
/// as defined in Section 5.2.  The semantics of such parameters is left
/// to site policy and is outside the scope of this document.
///
/// The critical flag is intended to permit future versions CAA to
/// introduce new semantics that MUST be understood for correct
/// processing of the record, preventing conforming CAs that do not
/// recognize the new semantics from issuing certificates for the
/// indicated domains.
///
/// In the following example, the property 'tbs' is flagged as critical.
/// Neither the example.net CA nor any other issuer is authorized to
/// issue under either policy unless the processing rules for the 'tbs'
/// property tag are understood.
///
/// $ORIGIN example.com
/// .       CAA 0 issue "ca.example.net; policy=ev"
/// .       CAA 128 tbs "Unknown"
///
/// Note that the above restrictions only apply at certificate issue.
/// Since the validity of an end entity certificate is typically a year
/// or more, it is quite possible that the CAA records published at a
/// domain will change between the time a certificate was issued and
/// validation by a relying party.
/// ```
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CAA {
    issuer_critical: bool,
    property: Property,
    tag: Tag,
}

/// Specifies in what contexts this key may be trusted for use
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Property {
    /// The issue property
    ///    entry authorizes the holder of the domain name <Issuer Domain
    ///    Name> or a party acting under the explicit authority of the holder
    ///    of that domain name to issue certificates for the domain in which
    ///    the property is published.
    Issue,
    /// The issuewild
    ///    property entry authorizes the holder of the domain name <Issuer
    ///    Domain Name> or a party acting under the explicit authority of the
    ///    holder of that domain name to issue wildcard certificates for the
    ///    domain in which the property is published.
    IssueWild,
    /// Specifies a URL to which an issuer MAY report
    ///    certificate issue requests that are inconsistent with the issuer's
    ///    Certification Practices or Certificate Policy, or that a
    ///    Certificate Evaluator may use to report observation of a possible
    ///    policy violation. The Incident Object Description Exchange Format
    ///    (IODEF) format is used [RFC5070].
    Iodef,
    /// Unknown format to TRust-DNS
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Tag {
    Issue{ name: Name, key_values: Vec<KeyValue>}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KeyValue {
    key: String,
    value: String,
}

pub fn read(decoder: &mut BinDecoder) -> ProtoResult<CAA> {
    unimplemented!()
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, opt: &CAA) -> ProtoResult<()> {
    unimplemented!()
}