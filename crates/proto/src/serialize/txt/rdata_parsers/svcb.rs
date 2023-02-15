// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-2.2)
///
/// ```text
/// 2.1.  Zone file presentation format
///
///   The presentation format of the record is:
///
///   Name TTL IN SVCB SvcPriority TargetName SvcParams
///
///   The SVCB record is defined specifically within the Internet ("IN")
///   Class ([RFC1035]).
///
///   SvcPriority is a number in the range 0-65535, TargetName is a domain
///   name, and the SvcParams are a whitespace-separated list, with each
///   SvcParam consisting of a SvcParamKey=SvcParamValue pair or a
///   standalone SvcParamKey.  SvcParamKeys are subject to IANA control
///   (Section 14.3).
///
///   Each SvcParamKey SHALL appear at most once in the SvcParams.  In
///   presentation format, SvcParamKeys are lower-case alphanumeric
///   strings.  Key names should contain 1-63 characters from the ranges
///   "a"-"z", "0"-"9", and "-".  In ABNF [RFC5234],
///
///   alpha-lc      = %x61-7A   ;  a-z
///   SvcParamKey   = 1*63(alpha-lc / DIGIT / "-")
///   SvcParam      = SvcParamKey ["=" SvcParamValue]
///   SvcParamValue = char-string
///   value         = *OCTET
///
///   The SvcParamValue is parsed using the character-string decoding
///   algorithm (Appendix A), producing a "value".  The "value" is then
///   validated and converted into wire-format in a manner specific to each
///   key.
///
///   When the "=" is omitted, the "value" is interpreted as empty.
///
///   Unrecognized keys are represented in presentation format as
///   "keyNNNNN" where NNNNN is the numeric value of the key type without
///   leading zeros.  A SvcParam in this form SHALL be parsed as specified
///   above, and the decoded "value" SHALL be used as its wire format
///   encoding.
///
///   For some SvcParamKeys, the "value" corresponds to a list or set of
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

    // Loop over all of the
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
        let value = key_value.next();
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
        SvcParamKey::EchConfig => parse_ech_config(value),
        SvcParamKey::Ipv6Hint => parse_ipv6_hint(value),
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-7)
/// ```text
/// The presentation "value" SHALL be a comma-separated list
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
///   echconfig=... key65333=ex1 key65444=ex2 mandatory=key65444,echconfig
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-6.1)
/// ```text
/// ALPNs are identified by their registered "Identification Sequence"
///   ("alpn-id"), which is a sequence of 1-255 octets.
///
///   alpn-id = 1*255OCTET
///
///   The presentation "value" SHALL be a comma-separated list
///   (Appendix A.1) of one or more "alpn-id"s.
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-6.1)
/// ```text
/// For "no-default-alpn", the presentation and wire format values MUST
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-6.2)
/// ```text
/// The presentation "value" of the SvcParamValue is a single decimal
///   integer between 0 and 65535 in ASCII.  Any other "value" (e.g. an
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-6.4)
/// ```text
/// The presentation "value" SHALL be a comma-separated list
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

/// As the documentation states, the presentation format (what this function reads) must be a BASE64 encoded string.
///   trust-dns will decode the BASE64 during parsing and stores the internal data as the raw bytes.
///
/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-9)
/// ```text
/// In presentation format, the value is a
///   single ECHConfigs encoded in Base64 [base64].  Base64 is used here to
///   simplify integration with TLS server software.  To enable simpler
///   parsing, this SvcParam MUST NOT contain escape sequences.
/// ```
fn parse_ech_config(value: Option<&str>) -> Result<SvcParamValue, ParseError> {
    let value = value.ok_or_else(|| {
        ParseError::from(ParseErrorKind::Message(
            "expected a base64 encoded string for EchConfig",
        ))
    })?;

    let value = parse_char_data(value)?;
    let ech_config_bytes = data_encoding::BASE64.decode(value.as_bytes())?;
    Ok(SvcParamValue::EchConfig(EchConfig(ech_config_bytes)))
}

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-6.4)
/// ```text
/// The presentation "value" SHALL be a comma-separated list
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

/// [draft-ietf-dnsop-svcb-https-03 SVCB and HTTPS RRs for DNS, February 2021](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-03#section-2.1)
/// ```text
/// Unrecognized keys are represented in presentation format as
///   "keyNNNNN" where NNNNN is the numeric value of the key type without
///   leading zeros.  A SvcParam in this form SHALL be parsed as specified
///   above, and the decoded "value" SHALL be used as its wire format
///   encoding.
///
///   For some SvcParamKeys, the "value" corresponds to a list or set of
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

    let values = value.trim_end_matches(',').split(',');
    for value in values {
        let value = parse_char_data(value)?;
        let value = T::from_str(&value).map_err(|e| e.into())?;
        result.push(value);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::{
        rr::{rdata::HTTPS, RecordData},
        serialize::txt::{Lexer, Parser},
    };

    use super::*;

    // this assumes that only a single record is parsed
    // TODO: make Parser return an iterator over all records in a stream.
    fn parse_record<D: RecordData>(txt: &str) -> D {
        let lex = Lexer::new(txt);
        let mut parser = Parser::new();

        let records = parser
            .parse(lex, Some(Name::root()))
            .expect("failed to parse record")
            .1;
        let record_set = records.into_iter().next().expect("no record found").1;
        record_set
            .into_iter()
            .next()
            .unwrap()
            .data()
            .and_then(D::try_borrow)
            .expect("Not the correct record")
            .clone()
    }

    #[test]
    fn test_parsing() {
        let svcb: SVCB = parse_record("crypto.cloudflare.com. 299 IN SVCB 1 . alpn=h2, ipv4hint=162.159.135.79,162.159.136.79, echconfig=\"/gkAQwATY2xvdWRmbGFyZS1lc25pLmNvbQAgUbBtC3UeykwwE6C87TffqLJ/1CeaAvx3iESGyds85l8AIAAEAAEAAQAAAAA=\" ipv6hint=2606:4700:7::a29f:874f,2606:4700:7::a29f:884f,");

        assert_eq!(svcb.svc_priority(), 1);
        assert_eq!(*svcb.target_name(), Name::root());

        let mut params = svcb.svc_params().iter();

        // alpn
        let param = params.next().expect("not alpn");
        assert_eq!(param.0, SvcParamKey::Alpn);
        assert_eq!(param.1.as_alpn().expect("not alpn").0, &["h2"]);

        // ipv4 hint
        let param = params.next().expect("ipv4hint");
        assert_eq!(SvcParamKey::Ipv4Hint, param.0);
        assert_eq!(
            param.1.as_ipv4_hint().expect("ipv4hint").0,
            &[A::new(162, 159, 135, 79), A::new(162, 159, 136, 79)]
        );

        // echconfig
        let param = params.next().expect("echconfig");
        assert_eq!(SvcParamKey::EchConfig, param.0);
        assert_eq!(
            param.1.as_ech_config().expect("echconfig").0,
            data_encoding::BASE64.decode("/gkAQwATY2xvdWRmbGFyZS1lc25pLmNvbQAgUbBtC3UeykwwE6C87TffqLJ/1CeaAvx3iESGyds85l8AIAAEAAEAAQAAAAA=".as_bytes()).unwrap()
        );

        // ipv6 hint
        let param = params.next().expect("ipv6hint");
        assert_eq!(SvcParamKey::Ipv6Hint, param.0);
        assert_eq!(
            param.1.as_ipv6_hint().expect("ipv6hint").0,
            &[
                AAAA::new(0x2606, 0x4700, 0x7, 0, 0, 0, 0xa29f, 0x874f),
                AAAA::new(0x2606, 0x4700, 0x7, 0, 0, 0, 0xa29f, 0x884f)
            ]
        );
    }

    #[test]
    fn test_parse_display() {
        let svcb: SVCB = parse_record("crypto.cloudflare.com. 299 IN SVCB 1 . alpn=h2, ipv4hint=162.159.135.79,162.159.136.79, echconfig=\"/gkAQwATY2xvdWRmbGFyZS1lc25pLmNvbQAgUbBtC3UeykwwE6C87TffqLJ/1CeaAvx3iESGyds85l8AIAAEAAEAAQAAAAA=\" ipv6hint=2606:4700:7::a29f:874f,2606:4700:7::a29f:884f,");

        let svcb_display = svcb.to_string();

        // add back the name, etc...
        let svcb_display = format!("crypto.cloudflare.com. 299 IN SVCB {svcb_display}");
        let svcb_display = parse_record(&svcb_display);

        assert_eq!(svcb, svcb_display);
    }

    /// sanity check for https
    #[test]
    fn test_parsing_https() {
        let svcb: HTTPS = parse_record("crypto.cloudflare.com. 299 IN HTTPS 1 . alpn=h2, ipv4hint=162.159.135.79,162.159.136.79, echconfig=\"/gkAQwATY2xvdWRmbGFyZS1lc25pLmNvbQAgUbBtC3UeykwwE6C87TffqLJ/1CeaAvx3iESGyds85l8AIAAEAAEAAQAAAAA=\" ipv6hint=2606:4700:7::a29f:874f,2606:4700:7::a29f:884f,");

        assert_eq!(svcb.svc_priority(), 1);
        assert_eq!(*svcb.target_name(), Name::root());
    }
}
