// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! SVCB records in presentation format

use std::str::FromStr;

use crate::{
    rr::{
        rdata::{svcb::*, A, AAAA},
        Name,
    },
    serialize::txt::{
        errors::{ParseError, ParseErrorKind, ParseResult},
        Lexer, Token,
    },
};

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-2.1)
///
/// ```text
/// 2.1.  Zone file presentation format
///
///   The presentation format <RDATA> of the record ([RFC1035]) has the form:
///
///   SvcPriority TargetName SvcParams
///
///   The SVCB record is defined specifically within the Internet ("IN")
///   Class ([RFC1035]).
///
///   SvcPriority is a number in the range 0-65535, TargetName is a
///   <domain-name> ([RFC1035], Section 5.1), and the SvcParams are
///   a whitespace-separated list, with each SvcParam consisting of a
///   SvcParamKey=SvcParamValue pair or a standalone SvcParamKey.  
///   SvcParamKeys are registered by IANA  (Section 14.3).
///
///   Each SvcParamKey SHALL appear at most once in the SvcParams.  In
///   presentation format, SvcParamKeys are lowercase alphanumeric
///   strings.  Key names should contain 1-63 characters from the ranges
///   "a"-"z", "0"-"9", and "-".  In ABNF [RFC5234],
///
///   alpha-lc      = %x61-7A   ;  a-z
///   SvcParamKey   = 1*63(alpha-lc / DIGIT / "-")
///   SvcParam      = SvcParamKey ["=" SvcParamValue]
///   SvcParamValue = char-string ; See Appendix A.
///   value         = *OCTET ; Value before key-specific parsing
///
///   The SvcParamValue is parsed using the character-string decoding
///   algorithm (Appendix A), producing a value.  The value is then
///   validated and converted into wire-format in a manner specific to each
///   key.
///
///   When the optional "=" and SvcParamValue are omitted, the value is
///   interpreted as empty.
///
///   Arbitrary keys can be represented using the unknown-key presentation
///   format "keyNNNNN" where NNNNN is the numeric value of the key type
///   without leading zeros. A SvcParam in this form SHALL be parsed as
///   specified above, and the decoded value SHALL be used as its wire-format
///   encoding.
///
///   For some SvcParamKeys, the value corresponds to a list or set of
///   items.  Presentation formats for such keys SHOULD use a comma-
///   separated list (Appendix A.1).
///
///   SvcParams in presentation format MAY appear in any order, but keys
///   MUST NOT be repeated.
/// ```
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<SVCB> {
    // SvcPriority
    let svc_priority: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("SvcPriority".to_string())))
        .and_then(|s| s.parse().map_err(Into::into))?;

    // svcb target
    let target_name: Name = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("Target".to_string())))
        .and_then(|s| Name::from_str(s).map_err(ParseError::from))?;

    // Loop over all of the service parameters
    let mut svc_params = Vec::new();
    for token in tokens {
        // first need to split the key and (optional) value
        let mut key_value = token.splitn(2, '=');
        let key = key_value.next().ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken(
                "SVCB SvcbParams missing".to_string(),
            ))
        })?;

        // get the value, and remove any quotes
        let mut value = key_value.next();
        if let Some(value) = value.as_mut() {
            if value.starts_with('"') && value.ends_with('"') {
                *value = &value[1..value.len() - 1];
            }
        }
        svc_params.push(into_svc_param(key, value)?);
    }

    Ok(SVCB::new(svc_priority, target_name, svc_params))
}

// first take the param and convert to
fn into_svc_param(
    key: &str,
    value: Option<&str>,
) -> Result<(SvcParamKey, SvcParamValue), ParseError> {
    let key = SvcParamKey::from_str(key)?;
    let value = parse_value(key, value)?;

    Ok((key, value))
}

fn parse_value(key: SvcParamKey, value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    match key {
        SvcParamKey::Mandatory => parse_mandatory(value),
        SvcParamKey::Alpn => parse_alpn(value),
        SvcParamKey::NoDefaultAlpn => parse_no_default_alpn(value),
        SvcParamKey::Port => parse_port(value),
        SvcParamKey::Ipv4Hint => parse_ipv4_hint(value),
        SvcParamKey::Ipv6Hint => parse_ipv6_hint(value),
        SvcParamKey::EchConfigList => parse_ech_config(value),
        SvcParamKey::Key(_) => parse_unknown(value),
        SvcParamKey::Key65535 | SvcParamKey::Unknown(_) => {
            Err(ParseError::from(ParseErrorKind::Message(
                "Bad Key type or unsupported, see generic key option, e.g. key1234",
            )))
        }
    }
}

fn parse_char_data(value: &str) -> Result<String, ParseError> {
    let mut lex = Lexer::new(value);
    let ch_data = lex
        .next_token()?
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("expected character data")))?;

    match ch_data {
        Token::CharData(data) => Ok(data),
        _ => Err(ParseError::from(ParseErrorKind::Message(
            "expected character data",
        ))),
    }
}

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-8)
///
/// ```text
///   The presentation value SHALL be a comma-separated list
///   (Appendix A.1) of one or more valid SvcParamKeys, either by their
///   registered name or in the unknown-key format (Section 2.1).  Keys MAY
///   appear in any order, but MUST NOT appear more than once.  For self-
///   consistency (Section 2.4.3), listed keys MUST also appear in the
///   SvcParams.
///
///   To enable simpler parsing, this SvcParamValue MUST NOT contain escape
///   sequences.
///
///   For example, the following is a valid list of SvcParams:
///
///   ipv6hint=... key65333=ex1 key65444=ex2 mandatory=key65444,ipv6hint
/// ```
///
/// Currently this does not validate that the mandatory section matches the other keys
fn parse_mandatory(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message(
            "expected at least one Mandatory field",
        ))
    })?;

    let mandatories = parse_list::<SvcParamKey>(value)?;
    Ok(SvcParamValue::Mandatory(Mandatory(mandatories)))
}

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-7.1.1)
///
/// ```text
///   ALPNs are identified by their registered "Identification Sequence"
///   ("alpn-id"), which is a sequence of 1-255 octets.
///
///   alpn-id = 1*255OCTET
///
///   For "alpn", the presentation value SHALL be a comma-separated list
///   (Appendix A.1) of one or more alpn-ids.
/// ```
///
/// This does not currently check to see if the ALPN code is legitimate
fn parse_alpn(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message("expected at least one ALPN code"))
    })?;

    let alpns = parse_list::<String>(value).expect("infallible");
    Ok(SvcParamValue::Alpn(Alpn(alpns)))
}

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-7.1.1)
///
/// ```text
///   For "no-default-alpn", the presentation and wire format values MUST
///   be empty.  When "no-default-alpn" is specified in an RR, "alpn" must
///   also be specified in order for the RR to be "self-consistent"
///   (Section 2.4.3).
/// ```
fn parse_no_default_alpn(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    if value.is_some() {
        return Err(ParseErrorKind::Message("no value expected for NoDefaultAlpn").into());
    }

    Ok(SvcParamValue::NoDefaultAlpn)
}

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-7.2)
///
/// ```text
///   The presentation value of the SvcParamValue is a single decimal
///   integer between 0 and 65535 in ASCII.  Any other value (e.g. an
///   empty value) is a syntax error.  To enable simpler parsing, this
///   SvcParam MUST NOT contain escape sequences.
/// ```
fn parse_port(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message("a port number for the port option"))
    })?;

    let value = parse_char_data(value)?;
    let port = u16::from_str(&value)?;
    Ok(SvcParamValue::Port(port))
}

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-7.3)
///
/// ```text
///   The presentation value SHALL be a comma-separated list
///   (Appendix A.1) of one or more IP addresses of the appropriate family
///   in standard textual format [RFC5952].  To enable simpler parsing,
///   this SvcParamValue MUST NOT contain escape sequences.
/// ```
fn parse_ipv4_hint(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message("expected at least one ipv4 hint"))
    })?;

    let hints = parse_list::<A>(value)?;
    Ok(SvcParamValue::Ipv4Hint(IpHint(hints)))
}

/// [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-7.3)
///
/// ```text
///   The presentation value SHALL be a comma-separated list
///   (Appendix A.1) of one or more IP addresses of the appropriate family
///   in standard textual format [RFC5952].  To enable simpler parsing,
///   this SvcParamValue MUST NOT contain escape sequences.
/// ```
fn parse_ipv6_hint(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message("expected at least one ipv6 hint"))
    })?;

    let hints = parse_list::<AAAA>(value)?;
    Ok(SvcParamValue::Ipv6Hint(IpHint(hints)))
}

/// As the documentation states, the presentation format (what this function outputs) must be a BASE64 encoded string.
///   hickory-dns will encode to BASE64 during formatting of the internal data, and output the BASE64 value.
///
/// [draft-ietf-tls-svcb-ech-01 Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings, Sep 2024](https://datatracker.ietf.org/doc/html/draft-ietf-tls-svcb-ech-01)
/// ```text
///  In presentation format, the value is the ECHConfigList in Base 64 Encoding
///  (Section 4 of [RFC4648]). Base 64 is used here to simplify integration with
///  TLS server software. To enable simpler parsing, this SvcParam MUST NOT
///  contain escape sequences.
/// ```
fn parse_ech_config(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message(
            "expected a base64 encoded string for EchConfig",
        ))
    })?;

    let value = parse_char_data(value)?;
    let ech_config_bytes = data_encoding::BASE64.decode(value.as_bytes())?;
    Ok(SvcParamValue::EchConfigList(EchConfigList(
        ech_config_bytes,
    )))
}

///  [RFC 9460 SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#section-2.1)
///
/// ```text
///   Arbitrary keys can be represented using the unknown-key presentation
///   format "keyNNNNN" where NNNNN is the numeric value of the key type
///   without leading zeros. A SvcParam in this form SHALL be parsed as specified
///   above, and the decoded value SHALL be used as its wire-format encoding.
///
///   For some SvcParamKeys, the value corresponds to a list or set of
///   items.  Presentation formats for such keys SHOULD use a comma-
///   separated list (Appendix A.1).
///
///   SvcParams in presentation format MAY appear in any order, but keys
///   MUST NOT be repeated.
/// ```
fn parse_unknown(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let unknown: Vec<u8> = if let Some(value) = value {
        value.as_bytes().to_vec()
    } else {
        Vec::new()
    };

    Ok(SvcParamValue::Unknown(Unknown(unknown)))
}

fn parse_list<T>(value: &str) -> Result<Vec<T>, ParseError>
where
    T: FromStr,
    T::Err: Into<ParseError>,
{
    let mut result = Vec::new();
    let mut current_value = String::new();
    let mut escaping = false;

    for c in value.chars() {
        match (c, escaping) {
            // End of value
            (',', false) => {
                result.push(T::from_str(&parse_char_data(&current_value)?).map_err(Into::into)?);
                current_value.clear()
            }
            // Start of escape sequence
            ('\\', false) => escaping = true,
            // Comma inside escape sequence
            (',', true) => {
                current_value.push(',');
                escaping = false
            }
            // Regular character inside escape sequence
            (_, true) => {
                current_value.push(c);
                escaping = false
            }
            // Regular character
            (_, false) => current_value.push(c),
        }
    }

    // Push the remaining value if there's any
    if !current_value.is_empty() {
        result.push(T::from_str(&parse_char_data(&current_value)?).map_err(Into::into)?);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::{
        rr::{rdata::HTTPS, RecordData},
        serialize::txt::Parser,
    };

    use super::*;

    // this assumes that only a single record is parsed
    // TODO: make Parser return an iterator over all records in a stream.
    fn parse_record<D: RecordData>(txt: &str) -> D {
        let records = Parser::new(txt, None, Some(Name::root()))
            .parse()
            .expect("failed to parse record")
            .1;
        let record_set = records.into_iter().next().expect("no record found").1;
        D::try_borrow(record_set.into_iter().next().unwrap().data())
            .expect("Not the correct record")
            .clone()
    }

    #[test]
    fn test_parsing() {
        let svcb: HTTPS = parse_record(CF_HTTPS_RECORD);

        assert_eq!(svcb.svc_priority(), 1);
        assert_eq!(*svcb.target_name(), Name::root());

        let mut params = svcb.svc_params().iter();

        // alpn
        let param = params.next().expect("not alpn");
        assert_eq!(param.0, SvcParamKey::Alpn);
        assert_eq!(param.1.as_alpn().expect("not alpn").0, &["http/1.1", "h2"]);

        // ipv4 hint
        let param = params.next().expect("ipv4hint");
        assert_eq!(SvcParamKey::Ipv4Hint, param.0);
        assert_eq!(
            param.1.as_ipv4_hint().expect("ipv4hint").0,
            &[A::new(162, 159, 137, 85), A::new(162, 159, 138, 85)]
        );

        // echconfig
        let param = params.next().expect("echconfig");
        assert_eq!(SvcParamKey::EchConfigList, param.0);
        assert_eq!(
            param.1.as_ech_config_list().expect("ech").0,
            data_encoding::BASE64.decode(b"AEX+DQBBtgAgACBMmGJQR02doup+5VPMjYpe5HQQ/bpntFCxDa8LT2PLAgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=").unwrap()
        );

        // ipv6 hint
        let param = params.next().expect("ipv6hint");
        assert_eq!(SvcParamKey::Ipv6Hint, param.0);
        assert_eq!(
            param.1.as_ipv6_hint().expect("ipv6hint").0,
            &[
                AAAA::new(0x2606, 0x4700, 0x7, 0, 0, 0, 0xa29f, 0x8955),
                AAAA::new(0x2606, 0x4700, 0x7, 0, 0, 0, 0xa29f, 0x8a5)
            ]
        );
    }

    #[test]
    fn test_parse_display() {
        let svcb: SVCB = parse_record(CF_SVCB_RECORD);

        let svcb_display = svcb.to_string();

        // add back the name, etc...
        let svcb_display = format!("crypto.cloudflare.com. 299 IN SVCB {svcb_display}");
        let svcb_display = parse_record(&svcb_display);

        assert_eq!(svcb, svcb_display);
    }

    /// sanity check for https
    #[test]
    fn test_parsing_https() {
        let records = [GOOGLE_HTTPS_RECORD, CF_HTTPS_RECORD];
        for record in records.iter() {
            let svcb: HTTPS = parse_record(record);

            assert_eq!(svcb.svc_priority(), 1);
            assert_eq!(*svcb.target_name(), Name::root());
        }
    }

    /// Test with RFC 9460 Appendix D test vectors
    /// <https://datatracker.ietf.org/doc/html/rfc9460#appendix-D>
    // TODO(XXX): Consider adding the negative "Failure Cases" from D.3.
    #[test]
    fn test_rfc9460_vectors() {
        #[derive(Debug)]
        struct TestVector {
            record: &'static str,
            record_type: RecordType,
            target_name: Name,
            priority: u16,
            params: Vec<(SvcParamKey, SvcParamValue)>,
        }

        #[derive(Debug)]
        enum RecordType {
            SVCB,
            HTTPS,
        }

        // NOTE: In each case the test vector from the RFC was augmented with a TTL (42 in each
        //       case). The parser requires this but the test vectors do not include it.
        let vectors: [TestVector; 9] = [
            // https://datatracker.ietf.org/doc/html/rfc9460#appendix-D.1
            // Figure 2: AliasMode
            TestVector {
                record: "example.com. 42  HTTPS   0 foo.example.com.",
                record_type: RecordType::HTTPS,
                target_name: Name::from_str("foo.example.com.").unwrap(),
                priority: 0,
                params: Vec::new(),
            },
            // https://datatracker.ietf.org/doc/html/rfc9460#appendix-D.2
            // Figure 3: TargetName Is "."
            TestVector {
                record: "example.com. 42  SVCB   1 .",
                record_type: RecordType::SVCB,
                target_name: Name::from_str(".").unwrap(),
                priority: 1,
                params: Vec::new(),
            },
            // Figure 4: Specifies a Port
            TestVector {
                record: "example.com. 42  SVCB   16 foo.example.com. port=53",
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.com").unwrap(),
                priority: 16,
                params: vec![(SvcParamKey::Port, SvcParamValue::Port(53))],
            },
            // Figure 5: A Generic Key and Unquoted Value
            TestVector {
                record: "example.com. 42  SVCB   1 foo.example.com. key667=hello",
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.com.").unwrap(),
                priority: 1,
                params: vec![(
                    SvcParamKey::Key(667),
                    SvcParamValue::Unknown(Unknown(b"hello".into())),
                )],
            },
            // Figure 6: A Generic Key and Quoted Value with a Decimal Escape
            TestVector {
                record: r#"example.com. 42  SVCB   1 foo.example.com. key667="hello\210qoo""#,
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.com.").unwrap(),
                priority: 1,
                params: vec![(
                    SvcParamKey::Key(667),
                    SvcParamValue::Unknown(Unknown(b"hello\\210qoo".into())),
                )],
            },
            // Figure 7: Two Quoted IPv6 Hints
            TestVector {
                record: r#"example.com. 42  SVCB   1 foo.example.com. (ipv6hint="2001:db8::1,2001:db8::53:1")"#,
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.com.").unwrap(),
                priority: 1,
                params: vec![(
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(vec![
                        AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                        AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x53, 1),
                    ])),
                )],
            },
            // Figure 8: An IPv6 Hint Using the Embedded IPv4 Syntax
            TestVector {
                record: r#"example.com.  42 SVCB   1 example.com. (ipv6hint="2001:db8:122:344::192.0.2.33")"#,
                record_type: RecordType::SVCB,
                target_name: Name::from_str("example.com.").unwrap(),
                priority: 1,
                params: vec![(
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(
                        0x2001, 0xdb8, 0x122, 0x344, 0, 0, 0xc000, 0x221,
                    )])),
                )],
            },
            // Figure 9: SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format
            TestVector {
                record: r#"example.com. 42  SVCB   16 foo.example.org. (alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1)"#,
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.org.").unwrap(),
                priority: 16,
                params: vec![
                    (
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h2".to_owned(), "h3-19".to_owned()])),
                    ),
                    (
                        SvcParamKey::Mandatory,
                        SvcParamValue::Mandatory(Mandatory(vec![
                            SvcParamKey::Ipv4Hint,
                            SvcParamKey::Alpn,
                        ])),
                    ),
                    (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A::new(192, 0, 2, 1)])),
                    ),
                ],
            },
            // Figure 10: An "alpn" Value with an Escaped Comma and an Escaped Backslash in Two Presentation Formats
            TestVector {
                record: r#"example.com.  42  SVCB   16 foo.example.org. alpn="f\\\\oo\,bar,h2""#,
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.org.").unwrap(),
                priority: 16,
                params: vec![(
                    SvcParamKey::Alpn,
                    SvcParamValue::Alpn(Alpn(vec![r#"f\\oo,bar"#.to_owned(), "h2".to_owned()])),
                )],
            },
            /*
             * TODO(XXX): Parser does not replace escaped characters, does not see "\092," as
             *            an escaped delim.
            TestVector {
                record: r#"example.com.  42  SVCB   116 foo.example.org. alpn=f\\\092oo\092,bar,h2""#,
                record_type: RecordType::SVCB,
                target_name: Name::from_str("foo.example.org.").unwrap(),
                priority: 16,
                params: vec![(
                    SvcParamKey::Alpn,
                    SvcParamValue::Alpn(Alpn(vec![r#"f\\oo,bar"#.to_owned(), "h2".to_owned()])),
                )],
            },
            */
        ];

        for record in vectors {
            let expected_scvb = SVCB::new(record.priority, record.target_name, record.params);
            match record.record_type {
                RecordType::SVCB => {
                    let parsed: SVCB = parse_record(record.record);
                    assert_eq!(parsed, expected_scvb);
                }
                RecordType::HTTPS => {
                    let parsed: HTTPS = parse_record(record.record);
                    assert_eq!(parsed, HTTPS(expected_scvb));
                }
            };
        }
    }

    const CF_SVCB_RECORD: & str = "crypto.cloudflare.com. 1664 IN SVCB 1 . alpn=\"http/1.1,h2\" ipv4hint=162.159.137.85,162.159.138.85 ech=AEX+DQBBtgAgACBMmGJQR02doup+5VPMjYpe5HQQ/bpntFCxDa8LT2PLAgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7::a29f:8955,2606:4700:7::a29f:8a5";
    const CF_HTTPS_RECORD: &str = "crypto.cloudflare.com. 1664 IN HTTPS 1 . alpn=\"http/1.1,h2\" ipv4hint=162.159.137.85,162.159.138.85 ech=AEX+DQBBtgAgACBMmGJQR02doup+5VPMjYpe5HQQ/bpntFCxDa8LT2PLAgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= ipv6hint=2606:4700:7::a29f:8955,2606:4700:7::a29f:8a5";
    const GOOGLE_HTTPS_RECORD: &str = "google.com 21132 IN HTTPS 1 . alpn=\"h2,h3\"";
}
