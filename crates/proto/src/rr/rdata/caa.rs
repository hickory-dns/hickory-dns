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

use std::fmt;
use std::str;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::rr::domain::Name;
use crate::serialize::binary::*;
use url::Url;

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
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CAA {
    #[doc(hidden)]
    pub issuer_critical: bool,
    #[doc(hidden)]
    pub tag: Property,
    #[doc(hidden)]
    pub value: Value,
}

impl CAA {
    fn issue(
        issuer_critical: bool,
        tag: Property,
        name: Option<Name>,
        options: Vec<KeyValue>,
    ) -> Self {
        assert!(tag.is_issue() || tag.is_issuewild());

        Self {
            issuer_critical,
            tag,
            value: Value::Issuer(name, options),
        }
    }

    /// Creates a new CAA issue record data, the tag is `issue`
    ///
    /// # Arguments
    ///
    /// * `issuer_critical` - indicates that the corresponding property tag MUST be understood if the semantics of the CAA record are to be correctly interpreted by an issuer
    /// * `name` - authorized to issue certificates for the associated record label
    /// * `options` - additional options for the issuer, e.g. 'account', etc.
    pub fn new_issue(issuer_critical: bool, name: Option<Name>, options: Vec<KeyValue>) -> Self {
        Self::issue(issuer_critical, Property::Issue, name, options)
    }

    /// Creates a new CAA issue record data, the tag is `issuewild`
    ///
    /// # Arguments
    ///
    /// * `issuer_critical` - indicates that the corresponding property tag MUST be understood if the semantics of the CAA record are to be correctly interpreted by an issuer
    /// * `name` - authorized to issue certificates for the associated record label
    /// * `options` - additional options for the issuer, e.g. 'account', etc.
    pub fn new_issuewild(
        issuer_critical: bool,
        name: Option<Name>,
        options: Vec<KeyValue>,
    ) -> Self {
        Self::issue(issuer_critical, Property::IssueWild, name, options)
    }

    /// Creates a new CAA issue record data, the tag is `iodef`
    ///
    /// # Arguments
    ///
    /// * `issuer_critical` - indicates that the corresponding property tag MUST be understood if the semantics of the CAA record are to be correctly interpreted by an issuer
    /// * `url` - Url where issuer errors should be reported
    ///
    /// # Panics
    ///
    /// If `value` is not `Value::Issuer`
    pub fn new_iodef(issuer_critical: bool, url: Url) -> Self {
        Self {
            issuer_critical,
            tag: Property::Iodef,
            value: Value::Url(url),
        }
    }

    /// Indicates that the corresponding property tag MUST be understood if the semantics of the CAA record are to be correctly interpreted by an issuer
    pub fn issuer_critical(&self) -> bool {
        self.issuer_critical
    }

    /// The property tag, see struct documentation
    pub fn tag(&self) -> &Property {
        &self.tag
    }

    /// a potentially associated value with the property tag, see struct documentation
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Specifies in what contexts this key may be trusted for use
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
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
    ///    (IODEF) format is used [RFC5070](https://tools.ietf.org/html/rfc5070).
    Iodef,
    /// Unknown format to Trust-DNS
    Unknown(String),
}

impl Property {
    /// Convert to string form
    pub fn as_str(&self) -> &str {
        match *self {
            Property::Issue => "issue",
            Property::IssueWild => "issuewild",
            Property::Iodef => "iodef",
            Property::Unknown(ref property) => property,
        }
    }

    /// true if the property is `issue`
    pub fn is_issue(&self) -> bool {
        matches!(*self, Property::Issue)
    }

    /// true if the property is `issueworld`
    pub fn is_issuewild(&self) -> bool {
        matches!(*self, Property::IssueWild)
    }

    /// true if the property is `iodef`
    pub fn is_iodef(&self) -> bool {
        matches!(*self, Property::Iodef)
    }

    /// true if the property is not known to Trust-DNS
    pub fn is_unknown(&self) -> bool {
        matches!(*self, Property::Unknown(_))
    }
}

impl From<String> for Property {
    fn from(tag: String) -> Self {
        // RFC6488 section 5.1 states that "Matching of tag values is case
        // insensitive."
        let lower = tag.to_ascii_lowercase();
        match &lower as &str {
            "issue" => return Self::Issue,
            "issuewild" => return Self::IssueWild,
            "iodef" => return Self::Iodef,
            &_ => (),
        }

        Self::Unknown(tag)
    }
}

/// Potential values.
///
/// These are based off the Tag field:
///
/// `Issue` and `IssueWild` => `Issuer`,
/// `Iodef` => `Url`,
/// `Unknown` => `Unknown`,
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Value {
    /// Issuer authorized to issue certs for this zone, and any associated parameters
    Issuer(Option<Name>, Vec<KeyValue>),
    /// Url to which to send CA errors
    Url(Url),
    /// Unrecognized tag and value by Trust-DNS
    Unknown(Vec<u8>),
}

impl Value {
    /// true if this is an `Issuer`
    pub fn is_issuer(&self) -> bool {
        matches!(*self, Value::Issuer(..))
    }

    /// true if this is a `Url`
    pub fn is_url(&self) -> bool {
        matches!(*self, Value::Url(..))
    }

    /// true if this is an `Unknown`
    pub fn is_unknown(&self) -> bool {
        matches!(*self, Value::Unknown(..))
    }
}

fn read_value(
    tag: &Property,
    decoder: &mut BinDecoder<'_>,
    value_len: Restrict<u16>,
) -> ProtoResult<Value> {
    let value_len = value_len.map(|u| u as usize).unverified(/*used purely as length safely*/);
    match *tag {
        Property::Issue | Property::IssueWild => {
            let slice = decoder.read_slice(value_len)?.unverified(/*read_issuer verified as safe*/);
            let value = read_issuer(slice)?;
            Ok(Value::Issuer(value.0, value.1))
        }
        Property::Iodef => {
            let url = decoder.read_slice(value_len)?.unverified(/*read_iodef verified as safe*/);
            let url = read_iodef(url)?;
            Ok(Value::Url(url))
        }
        Property::Unknown(_) => Ok(Value::Unknown(
            decoder.read_vec(value_len)?.unverified(/*unknown will fail in usage*/),
        )),
    }
}

fn emit_value(encoder: &mut BinEncoder<'_>, value: &Value) -> ProtoResult<()> {
    match *value {
        Value::Issuer(ref name, ref key_values) => {
            // output the name
            if let Some(ref name) = *name {
                let name = name.to_string();
                encoder.emit_vec(name.as_bytes())?;
            }

            // if there was no name, then we just output ';'
            if name.is_none() && key_values.is_empty() {
                return encoder.emit(b';');
            }

            for key_value in key_values {
                encoder.emit(b';')?;
                encoder.emit(b' ')?;
                encoder.emit_vec(key_value.key.as_bytes())?;
                encoder.emit(b'=')?;
                encoder.emit_vec(key_value.value.as_bytes())?;
            }

            Ok(())
        }
        Value::Url(ref url) => {
            let url = url.as_str();
            let bytes = url.as_bytes();
            encoder.emit_vec(bytes)
        }
        Value::Unknown(ref data) => encoder.emit_vec(data),
    }
}

enum ParseNameKeyPairState {
    BeforeKey(Vec<KeyValue>),
    Key {
        first_char: bool,
        key: String,
        key_values: Vec<KeyValue>,
    },
    Value {
        key: String,
        value: String,
        key_values: Vec<KeyValue>,
    },
}

/// Reads the issuer field according to the spec
///
/// [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844#section-5.2)
///
/// ```text
/// 5.2.  CAA issue Property
///
///    The issue property tag is used to request that certificate issuers
///    perform CAA issue restriction processing for the domain and to grant
///    authorization to specific certificate issuers.
///
///    The CAA issue property value has the following sub-syntax (specified
///    in ABNF as per [RFC5234]).
///
///    issuevalue  = space [domain] space [";" *(space parameter) space]
///
///    domain = label *("." label)
///    label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
///
///    space = *(SP / HTAB)
///
///    parameter =  tag "=" value
///
///    tag = 1*(ALPHA / DIGIT)
///
///    value = *VCHAR
///
///    For consistency with other aspects of DNS administration, domain name
///    values are specified in letter-digit-hyphen Label (LDH-Label) form.
///
///    A CAA record with an issue parameter tag that does not specify a
///    domain name is a request that certificate issuers perform CAA issue
///    restriction processing for the corresponding domain without granting
///    authorization to any certificate issuer.
///
///    This form of issue restriction would be appropriate to specify that
///    no certificates are to be issued for the domain in question.
///
///    For example, the following CAA record set requests that no
///    certificates be issued for the domain 'nocerts.example.com' by any
///    certificate issuer.
///
///    nocerts.example.com       CAA 0 issue ";"
///
///    A CAA record with an issue parameter tag that specifies a domain name
///    is a request that certificate issuers perform CAA issue restriction
///    processing for the corresponding domain and grants authorization to
///    the certificate issuer specified by the domain name.
///
///    For example, the following CAA record set requests that no
///    certificates be issued for the domain 'certs.example.com' by any
///    certificate issuer other than the example.net certificate issuer.
///
///    certs.example.com       CAA 0 issue "example.net"
///
///    CAA authorizations are additive; thus, the result of specifying both
///    the empty issuer and a specified issuer is the same as specifying
///    just the specified issuer alone.
///
///    An issuer MAY choose to specify issuer-parameters that further
///    constrain the issue of certificates by that issuer, for example,
///    specifying that certificates are to be subject to specific validation
///    polices, billed to certain accounts, or issued under specific trust
///    anchors.
///
///    The semantics of issuer-parameters are determined by the issuer
///    alone.
/// ```
///
/// Updated parsing rules:
///
/// [RFC 6844bis, CAA Resource Record, May 2018](https://tools.ietf.org/html/draft-ietf-lamps-rfc6844bis-00)
/// [RFC 6844, CAA Record Extensions, May 2018](https://tools.ietf.org/html/draft-ietf-acme-caa-04)
///
/// This explicitly allows `-` in key names, diverging from the original RFC. To support this, key names will
/// allow `-` as non-starting characters. Additionally, this significantly relaxes the characters allowed in the value
/// to allow URL like characters (it does not validate URL syntax).
pub fn read_issuer(bytes: &[u8]) -> ProtoResult<(Option<Name>, Vec<KeyValue>)> {
    let mut byte_iter = bytes.iter();

    // we want to reuse the name parsing rules
    let name: Option<Name> = {
        let take_name = byte_iter.by_ref().take_while(|ch| char::from(**ch) != ';');
        let name_str = take_name.cloned().collect::<Vec<u8>>();

        if !name_str.is_empty() {
            let name_str = str::from_utf8(&name_str)?;
            Some(Name::parse(name_str, None)?)
        } else {
            None
        }
    };

    // initial state is looking for a key ';' is valid...
    let mut state = ParseNameKeyPairState::BeforeKey(vec![]);

    // run the state machine through all remaining data, collecting all key/value pairs.
    for ch in byte_iter {
        match state {
            // Name was already successfully parsed, otherwise we couldn't get here.
            ParseNameKeyPairState::BeforeKey(key_values) => {
                match char::from(*ch) {
                    // gobble ';', ' ', and tab
                    ';' | ' ' | '\u{0009}' => state = ParseNameKeyPairState::BeforeKey(key_values),
                    ch if ch.is_alphanumeric() && ch != '=' => {
                        // We found the beginning of a new Key
                        let mut key = String::new();
                        key.push(ch);

                        state = ParseNameKeyPairState::Key {
                            first_char: true,
                            key,
                            key_values,
                        }
                    }
                    ch => return Err(format!("bad character in CAA issuer key: {}", ch).into()),
                }
            }
            ParseNameKeyPairState::Key {
                first_char,
                mut key,
                key_values,
            } => {
                match char::from(*ch) {
                    // transition to value
                    '=' => {
                        let value = String::new();
                        state = ParseNameKeyPairState::Value {
                            key,
                            value,
                            key_values,
                        }
                    }
                    // push onto the existing key
                    ch if (ch.is_alphanumeric() || (!first_char && ch == '-'))
                        && ch != '='
                        && ch != ';' =>
                    {
                        key.push(ch);
                        state = ParseNameKeyPairState::Key {
                            first_char: false,
                            key,
                            key_values,
                        }
                    }
                    ch => return Err(format!("bad character in CAA issuer key: {}", ch).into()),
                }
            }
            ParseNameKeyPairState::Value {
                key,
                mut value,
                mut key_values,
            } => {
                match char::from(*ch) {
                    // transition back to find another pair
                    ';' => {
                        key_values.push(KeyValue { key, value });
                        state = ParseNameKeyPairState::BeforeKey(key_values);
                    }
                    // push onto the existing key
                    ch if !ch.is_control() && !ch.is_whitespace() => {
                        value.push(ch);

                        state = ParseNameKeyPairState::Value {
                            key,
                            value,
                            key_values,
                        }
                    }
                    ch => return Err(format!("bad character in CAA issuer value: '{}'", ch).into()),
                }
            }
        }
    }

    // valid final states are BeforeKey, where there was a final ';' but nothing followed it.
    //                        Value, where we collected the final chars of the value, but no more data
    let key_values = match state {
        ParseNameKeyPairState::BeforeKey(key_values) => key_values,
        ParseNameKeyPairState::Value {
            key,
            value,
            mut key_values,
        } => {
            key_values.push(KeyValue { key, value });
            key_values
        }
        ParseNameKeyPairState::Key { key, .. } => {
            return Err(format!("key missing value: {}", key).into());
        }
    };

    Ok((name, key_values))
}

/// Incident Object Description Exchange Format
///
/// [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844#section-5.4)
///
/// ```text
/// 5.4.  CAA iodef Property
///
///    The iodef property specifies a means of reporting certificate issue
///    requests or cases of certificate issue for the corresponding domain
///    that violate the security policy of the issuer or the domain name
///    holder.
///
///    The Incident Object Description Exchange Format (IODEF) [RFC5070] is
///    used to present the incident report in machine-readable form.
///
///    The iodef property takes a URL as its parameter.  The URL scheme type
///    determines the method used for reporting:
///
///    mailto:  The IODEF incident report is reported as a MIME email
///       attachment to an SMTP email that is submitted to the mail address
///       specified.  The mail message sent SHOULD contain a brief text
///       message to alert the recipient to the nature of the attachment.
///
///    http or https:  The IODEF report is submitted as a Web service
///       request to the HTTP address specified using the protocol specified
///       in [RFC6546].
/// ```
pub fn read_iodef(url: &[u8]) -> ProtoResult<Url> {
    let url = str::from_utf8(url)?;
    let url = Url::parse(url)?;
    Ok(url)
}

/// Issuer key and value pairs.
///
/// See [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844#section-5.2)
/// for more explanation.
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KeyValue {
    key: String,
    value: String,
}

impl KeyValue {
    /// Construct a new KeyValue pair
    pub fn new<K: Into<String>, V: Into<String>>(key: K, value: V) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Gets a reference to the key of the pair.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Gets a reference to the value of the pair.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Read the binary CAA format
///
/// [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844#section-5.1)
///
/// ```text
/// 5.1.  Syntax
///
///   A CAA RR contains a single property entry consisting of a tag-value
///   pair.  Each tag represents a property of the CAA record.  The value
///   of a CAA property is that specified in the corresponding value field.
///
///   A domain name MAY have multiple CAA RRs associated with it and a
///   given property MAY be specified more than once.
///
///   The CAA data field contains one property entry.  A property entry
///   consists of the following data fields:
///
///   +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
///   | Flags          | Tag Length = n |
///   +----------------+----------------+...+---------------+
///   | Tag char 0     | Tag char 1     |...| Tag char n-1  |
///   +----------------+----------------+...+---------------+
///   +----------------+----------------+.....+----------------+
///   | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
///   +----------------+----------------+.....+----------------+
///
///   Where n is the length specified in the Tag length field and m is the
///   remaining octets in the Value field (m = d - n - 2) where d is the
///   length of the RDATA section.
///
///   The data fields are defined as follows:
///
///   Flags:  One octet containing the following fields:
///
///      Bit 0, Issuer Critical Flag:  If the value is set to '1', the
///         critical flag is asserted and the property MUST be understood
///         if the CAA record is to be correctly processed by a certificate
///         issuer.
///
///         A Certification Authority MUST NOT issue certificates for any
///         Domain that contains a CAA critical property for an unknown or
///         unsupported property tag that for which the issuer critical
///         flag is set.
///
///      Note that according to the conventions set out in [RFC1035], bit 0
///      is the Most Significant Bit and bit 7 is the Least Significant
///      Bit. Thus, the Flags value 1 means that bit 7 is set while a value
///      of 128 means that bit 0 is set according to this convention.
///
///      All other bit positions are reserved for future use.
///
///      To ensure compatibility with future extensions to CAA, DNS records
///      compliant with this version of the CAA specification MUST clear
///      (set to "0") all reserved flags bits.  Applications that interpret
///      CAA records MUST ignore the value of all reserved flag bits.
///
///   Tag Length:  A single octet containing an unsigned integer specifying
///      the tag length in octets.  The tag length MUST be at least 1 and
///      SHOULD be no more than 15.
///
///   Tag:  The property identifier, a sequence of US-ASCII characters.
///
///      Tag values MAY contain US-ASCII characters 'a' through 'z', 'A'
///      through 'Z', and the numbers 0 through 9.  Tag values SHOULD NOT
///      contain any other characters.  Matching of tag values is case
///      insensitive.
///
///      Tag values submitted for registration by IANA MUST NOT contain any
///      characters other than the (lowercase) US-ASCII characters 'a'
///      through 'z' and the numbers 0 through 9.
///
///   Value:  A sequence of octets representing the property value.
///      Property values are encoded as binary values and MAY employ sub-
///      formats.
///
///      The length of the value field is specified implicitly as the
///      remaining length of the enclosing Resource Record data field.
/// ```
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<CAA> {
    // the spec declares that other flags should be ignored for future compatibility...
    let issuer_critical: bool =
        decoder.read_u8()?.unverified(/*used as bitfield*/) & 0b1000_0000 != 0;

    let tag_len = decoder.read_u8()?;
    let value_len: Restrict<u16> = rdata_length
        .checked_sub(u16::from(tag_len.unverified(/*safe usage here*/)))
        .checked_sub(2)
        .map_err(|_| ProtoError::from("CAA tag character(s) out of bounds"))?;

    let tag = read_tag(decoder, tag_len)?;
    let tag = Property::from(tag);
    let value = read_value(&tag, decoder, value_len)?;

    Ok(CAA {
        issuer_critical,
        tag,
        value,
    })
}

// TODO: change this to return &str
fn read_tag(decoder: &mut BinDecoder<'_>, len: Restrict<u8>) -> ProtoResult<String> {
    let len = len
        .map(|len| len as usize)
        .verify_unwrap(|len| *len > 0 && *len <= 15)
        .map_err(|_| ProtoError::from("CAA tag length out of bounds, 1-15"))?;
    let mut tag = String::with_capacity(len);

    for _ in 0..len {
        let ch = decoder
            .pop()?
            .map(char::from)
            .verify_unwrap(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9'))
            .map_err(|_| ProtoError::from("CAA tag character(s) out of bounds"))?;

        tag.push(ch);
    }

    Ok(tag)
}

/// writes out the tag in binary form to the buffer, returning the number of bytes written
fn emit_tag(buf: &mut [u8], tag: &Property) -> ProtoResult<u8> {
    let property = tag.as_str();
    let property = property.as_bytes();

    let len = property.len();
    if len > ::std::u8::MAX as usize {
        return Err(format!("CAA property too long: {}", len).into());
    }
    if buf.len() < len {
        return Err(format!(
            "insufficient capacity in CAA buffer: {} for tag: {}",
            buf.len(),
            len
        )
        .into());
    }

    // copy into the buffer
    let buf = &mut buf[0..len];
    buf.copy_from_slice(property);

    Ok(len as u8)
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, caa: &CAA) -> ProtoResult<()> {
    let mut flags = 0_u8;

    if caa.issuer_critical {
        flags |= 0b1000_0000;
    }

    encoder.emit(flags)?;
    // TODO: it might be interesting to use the new place semantics here to output all the data, then place the length back to the beginning...
    let mut tag_buf = [0_u8; ::std::u8::MAX as usize];
    let len = emit_tag(&mut tag_buf, &caa.tag)?;

    // now write to the encoder
    encoder.emit(len)?;
    encoder.emit_vec(&tag_buf[0..len as usize])?;
    emit_value(encoder, &caa.value)?;

    Ok(())
}

impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let s = match self {
            Property::Issue => "issue",
            Property::IssueWild => "issuewild",
            Property::Iodef => "iodef",
            Property::Unknown(s) => s,
        };

        f.write_str(s)
    }
}

impl fmt::Display for Value {
    // https://datatracker.ietf.org/doc/html/rfc6844#section-5.1.1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("\"")?;

        match self {
            Value::Issuer(name, values) => {
                match name {
                    Some(name) => write!(f, "{}", name)?,
                    None => write!(f, ";")?,
                }

                if let Some(value) = values.first() {
                    write!(f, " {}", value)?;
                    for value in &values[1..] {
                        write!(f, "; {}", value)?;
                    }
                }
            }
            Value::Url(url) => write!(f, "{}", url)?,
            Value::Unknown(v) => write!(f, "{:?}", v)?,
        }

        f.write_str("\"")
    }
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&self.key)?;
        if !self.value.is_empty() {
            write!(f, "={}", self.value)?;
        }

        Ok(())
    }
}

// FIXME: this needs to be verified to be correct, add tests...
impl fmt::Display for CAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let critical = if self.issuer_critical { "1" } else { "0" };

        write!(
            f,
            "{critical} {tag} {value}",
            critical = critical,
            tag = self.tag,
            value = self.value
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;
    use std::str;

    #[test]
    fn test_read_tag() {
        let ok_under15 = b"abcxyzABCXYZ019";
        let mut decoder = BinDecoder::new(ok_under15);

        let read = read_tag(&mut decoder, Restrict::new(ok_under15.len() as u8))
            .expect("failed to read tag");

        assert_eq!(str::from_utf8(ok_under15).unwrap(), read);
    }

    #[test]
    fn test_bad_tag() {
        let bad_under15 = b"-";
        let mut decoder = BinDecoder::new(bad_under15);

        assert!(read_tag(&mut decoder, Restrict::new(bad_under15.len() as u8)).is_err());
    }

    #[test]
    fn test_too_short_tag() {
        let too_short = b"";
        let mut decoder = BinDecoder::new(too_short);

        assert!(read_tag(&mut decoder, Restrict::new(too_short.len() as u8)).is_err());
    }

    #[test]
    fn test_too_long_tag() {
        let too_long = b"0123456789abcdef";
        let mut decoder = BinDecoder::new(too_long);

        assert!(read_tag(&mut decoder, Restrict::new(too_long.len() as u8)).is_err());
    }

    #[test]
    fn test_from_str_property() {
        assert_eq!(Property::from("Issue".to_string()), Property::Issue);
        assert_eq!(Property::from("issueWild".to_string()), Property::IssueWild);
        assert_eq!(Property::from("iodef".to_string()), Property::Iodef);
        assert_eq!(
            Property::from("unknown".to_string()),
            Property::Unknown("unknown".to_string())
        );
    }

    #[test]
    fn test_read_issuer() {
        // (Option<Name>, Vec<KeyValue>)
        assert_eq!(
            read_issuer(b"ca.example.net; account=230123").unwrap(),
            (
                Some(Name::parse("ca.example.net", None).unwrap()),
                vec![KeyValue {
                    key: "account".to_string(),
                    value: "230123".to_string(),
                }],
            )
        );

        assert_eq!(
            read_issuer(b"ca.example.net").unwrap(),
            (Some(Name::parse("ca.example.net", None,).unwrap(),), vec![],)
        );
        assert_eq!(
            read_issuer(b"ca.example.net; policy=ev").unwrap(),
            (
                Some(Name::parse("ca.example.net", None).unwrap(),),
                vec![KeyValue {
                    key: "policy".to_string(),
                    value: "ev".to_string(),
                }],
            )
        );
        assert_eq!(
            read_issuer(b"ca.example.net; account=230123; policy=ev").unwrap(),
            (
                Some(Name::parse("ca.example.net", None).unwrap(),),
                vec![
                    KeyValue {
                        key: "account".to_string(),
                        value: "230123".to_string(),
                    },
                    KeyValue {
                        key: "policy".to_string(),
                        value: "ev".to_string(),
                    },
                ],
            )
        );
        assert_eq!(
            read_issuer(b"example.net; account-uri=https://example.net/account/1234; validation-methods=dns-01").unwrap(),
            (
                Some(Name::parse("example.net", None).unwrap(),),
                vec![
                    KeyValue {
                        key: "account-uri".to_string(),
                        value: "https://example.net/account/1234".to_string(),
                    },
                    KeyValue {
                        key: "validation-methods".to_string(),
                        value: "dns-01".to_string(),
                    },
                ],
            )
        );
        assert_eq!(read_issuer(b";").unwrap(), (None, vec![]));
    }

    #[test]
    fn test_read_iodef() {
        assert_eq!(
            read_iodef(b"mailto:security@example.com").unwrap(),
            Url::parse("mailto:security@example.com").unwrap()
        );
        assert_eq!(
            read_iodef(b"http://iodef.example.com/").unwrap(),
            Url::parse("http://iodef.example.com/").unwrap()
        );
    }

    fn test_encode_decode(rdata: CAA) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        emit(&mut encoder, &rdata).expect("failed to emit caa");
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata =
            read(&mut decoder, Restrict::new(bytes.len() as u16)).expect("failed to read back");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_encode_decode_issue() {
        test_encode_decode(CAA::new_issue(true, None, vec![]));
        test_encode_decode(CAA::new_issue(
            true,
            Some(Name::parse("example.com", None).unwrap()),
            vec![],
        ));
        test_encode_decode(CAA::new_issue(
            true,
            Some(Name::parse("example.com", None).unwrap()),
            vec![KeyValue::new("key", "value")],
        ));
        // technically the this parser supports this case, though it's not clear it's something the spec allows for
        test_encode_decode(CAA::new_issue(
            true,
            None,
            vec![KeyValue::new("key", "value")],
        ));
        // test fqdn
        test_encode_decode(CAA::new_issue(
            true,
            Some(Name::parse("example.com.", None).unwrap()),
            vec![],
        ));
    }

    #[test]
    fn test_encode_decode_issuewild() {
        test_encode_decode(CAA::new_issuewild(false, None, vec![]));
        // other variants handled in test_encode_decode_issue
    }

    #[test]
    fn test_encode_decode_iodef() {
        test_encode_decode(CAA::new_iodef(
            true,
            Url::parse("http://www.example.com").unwrap(),
        ));
        test_encode_decode(CAA::new_iodef(
            false,
            Url::parse("mailto:root@example.com").unwrap(),
        ));
    }

    fn test_encode(rdata: CAA, encoded: &[u8]) {
        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        emit(&mut encoder, &rdata).expect("failed to emit caa");
        let bytes = encoder.into_bytes();
        assert_eq!(bytes as &[u8], encoded);
    }

    #[test]
    fn test_encode_non_fqdn() {
        let name_bytes: &[u8] = b"issueexample.com";
        let header: &[u8] = &[128, 5];
        let encoded: Vec<u8> = header.iter().chain(name_bytes.iter()).cloned().collect();

        test_encode(
            CAA::new_issue(
                true,
                Some(Name::parse("example.com", None).unwrap()),
                vec![],
            ),
            &encoded,
        );
    }

    #[test]
    fn test_encode_fqdn() {
        let name_bytes: &[u8] = b"issueexample.com.";
        let header: [u8; 2] = [128, 5];
        let encoded: Vec<u8> = header.iter().chain(name_bytes.iter()).cloned().collect();

        test_encode(
            CAA::new_issue(
                true,
                Some(Name::parse("example.com.", None).unwrap()),
                vec![],
            ),
            &encoded,
        );
    }

    #[test]
    fn test_tostring() {
        let deny = CAA::new_issue(false, None, vec![]);
        assert_eq!(deny.to_string(), "0 issue \";\"");

        let empty_options = CAA::new_issue(
            false,
            Some(Name::parse("example.com", None).unwrap()),
            vec![],
        );
        assert_eq!(empty_options.to_string(), "0 issue \"example.com\"");

        let one_option = CAA::new_issue(
            false,
            Some(Name::parse("example.com", None).unwrap()),
            vec![KeyValue::new("one", "1")],
        );
        assert_eq!(one_option.to_string(), "0 issue \"example.com one=1\"");

        let two_options = CAA::new_issue(
            false,
            Some(Name::parse("example.com", None).unwrap()),
            vec![KeyValue::new("one", "1"), KeyValue::new("two", "2")],
        );
        assert_eq!(
            two_options.to_string(),
            "0 issue \"example.com one=1; two=2\""
        );
    }
}
