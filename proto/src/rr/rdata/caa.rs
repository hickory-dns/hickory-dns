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

use std::str;

use error::*;
use rr::domain::Name;
use serialize::binary::*;
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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CAA {
    issuer_critical: bool,
    tag: Property,
    value: Value,
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

impl From<String> for Property {
    fn from(tag: String) -> Property {
        match &tag as &str {
            "issue" => return Property::Issue,
            "issuewild" => return Property::IssueWild,
            "iodef" => return Property::Iodef,
            &_ => (),
        }

        Property::Unknown(tag)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Value {
    Issuer(Option<Name>, Vec<KeyValue>),
    Url(Url),
    Unknown(Vec<u8>),
}

fn read_value(tag: &Property, decoder: &mut BinDecoder, value_len: u16) -> ProtoResult<Value> {
    match *tag {
        Property::Issue | Property::IssueWild => {
            let slice = decoder.read_slice(value_len as usize)?;
            let value = read_issuer(slice)?;
            Ok(Value::Issuer(value.0, value.1))
        }
        Property::Iodef => {
            let url = decoder.read_slice(value_len as usize)?;
            let url = read_iodef(url)?;
            Ok(Value::Url(url))
        }
        Property::Unknown(_) => Ok(Value::Unknown(decoder.read_vec(value_len as usize)?)),
    }
}

enum ParseNameKeyPairState {
    BeforeKey(Vec<KeyValue>),
    Key {
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
fn read_issuer(bytes: &[u8]) -> ProtoResult<(Option<Name>, Vec<KeyValue>)> {
    let mut byte_iter = bytes.iter();

    // we want to reuse the name parsing rules
    let name: Option<Name> = {
        let take_name = byte_iter.by_ref().take_while(|ch| char::from(**ch) != ';');
        let name_str = take_name.cloned().collect::<Vec<u8>>();

        if name_str.len() > 0 {
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
                    ch @ _ if ch.is_alphanumeric() && ch != '=' => {
                        // We found the beginning of a new Key
                        let mut key = String::new();
                        key.push(ch);

                        state = ParseNameKeyPairState::Key { key, key_values }
                    }
                    ch @ _ => {
                        return Err(
                            ProtoErrorKind::Msg(
                                format!("bad character in CAA issuer key: {}", ch),
                            ).into(),
                        )
                    }
                }
            }
            ParseNameKeyPairState::Key {
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
                    ch @ _ if ch.is_alphanumeric() && ch != '=' && ch != ';' => {
                        key.push(ch);

                        state = ParseNameKeyPairState::Key { key, key_values }
                    }
                    ch @ _ => {
                        return Err(
                            ProtoErrorKind::Msg(
                                format!("bad character in CAA issuer key: {}", ch),
                            ).into(),
                        )
                    }
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
                    ch @ _ if ch.is_alphanumeric() => {
                        value.push(ch);

                        state = ParseNameKeyPairState::Value {
                            key,
                            value,
                            key_values,
                        }
                    }
                    ch @ _ => {
                        return Err(
                            ProtoErrorKind::Msg(
                                format!("bad character in CAA issuer value: {}", ch),
                            ).into(),
                        )
                    }
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
            return Err(
                ProtoErrorKind::Msg(format!("key missing value: {}", key)).into(),
            )
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
fn read_iodef(url: &[u8]) -> ProtoResult<Url> {
    let url = str::from_utf8(url)?;
    let url = Url::parse(url)?;
    Ok(url)
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KeyValue {
    key: String,
    value: String,
}

/// Read the bincary CAA format
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
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> ProtoResult<CAA> {
    // the spec declares that other flags should be ignored for future compatability...
    let issuer_critical: bool = decoder.read_u8()? & 0b1000_0000 != 0;
    let tag_len = decoder.read_u8()?;
    let value_len = (rdata_length - tag_len as u16) - 2;

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
fn read_tag(decoder: &mut BinDecoder, len: u8) -> ProtoResult<String> {
    if len == 0 || len > 15 {
        return Err(
            ProtoErrorKind::Message("CAA tag length out of bounds, 1-15").into(),
        );
    }
    let mut tag = String::with_capacity(len as usize);

    for _ in 0..len {
        let ch = char::from(decoder.pop()?);

        match ch {
            ch @ 'a'...'z' | ch @ 'A'...'Z' | ch @ '0'...'9' => {
                tag.push(ch);
            }
            _ => {
                return Err(
                    ProtoErrorKind::Message("CAA tag character(s) out of bounds").into(),
                )
            }
        }
    }

    Ok(tag)
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, opt: &CAA) -> ProtoResult<()> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use std::str;
    use serialize::binary::*;
    use super::*;

    #[test]
    fn test_read_tag() {
        let ok_under15 = b"abcxyzABCXYZ019";
        let mut decoder = BinDecoder::new(ok_under15);

        let read = read_tag(&mut decoder, ok_under15.len() as u8).expect("failed to read tag");

        assert_eq!(str::from_utf8(ok_under15).unwrap(), read);
    }

    #[test]
    fn test_bad_tag() {
        let bad_under15 = b"-";
        let mut decoder = BinDecoder::new(bad_under15);

        assert!(read_tag(&mut decoder, bad_under15.len() as u8).is_err());
    }

    #[test]
    fn test_too_short_tag() {
        let too_short = b"";
        let mut decoder = BinDecoder::new(too_short);

        assert!(read_tag(&mut decoder, too_short.len() as u8).is_err());
    }

    #[test]
    fn test_too_long_tag() {
        let too_long = b"0123456789abcdef";
        let mut decoder = BinDecoder::new(too_long);

        assert!(read_tag(&mut decoder, too_long.len() as u8).is_err());
    }

    #[test]
    fn test_from_str_property() {
        assert_eq!(Property::from("issue".to_string()), Property::Issue);
        assert_eq!(Property::from("issuewild".to_string()), Property::IssueWild);
        assert_eq!(Property::from("iodef".to_string()), Property::Iodef);
        assert_eq!(
            Property::from("unknown".to_string()),
            Property::Unknown("unknown".to_string())
        );
    }

    #[test]
    fn test_read_issuer() {
        // (Option<Name>, Vec<KeyValue>)
        assert_eq!(read_issuer(b"ca.example.net; account=230123").unwrap(), (
            Some(Name::parse("ca.example.net", None).unwrap()),
            vec![
                KeyValue {
                    key: "account".to_string(),
                    value: "230123".to_string(),
                },
            ],
        ));

        assert_eq!(read_issuer(b"ca.example.net").unwrap(), (
            Some(
                Name::parse(
                    "ca.example.net",
                    None,
                ).unwrap(),
            ),
            vec![],
        ));
        assert_eq!(read_issuer(b"ca.example.net; policy=ev").unwrap(), (
            Some(Name::parse("ca.example.net", None).unwrap()),
            vec![
                KeyValue {
                    key: "policy".to_string(),
                    value: "ev".to_string(),
                },
            ],
        ));
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
}