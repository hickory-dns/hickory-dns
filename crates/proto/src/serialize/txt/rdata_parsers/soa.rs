/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Parser for SOA text form

use alloc::string::ToString;

use crate::{
    rr::{domain::Name, rdata::SOA},
    serialize::txt::{
        errors::{ParseError, ParseErrorKind, ParseResult},
        zone,
    },
};

/// Parse the RData from a set of Tokens
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(
    mut tokens: I,
    origin: Option<&Name>,
) -> ParseResult<SOA> {
    let mname: Name = tokens
        .next()
        .ok_or_else(|| ParseErrorKind::MissingToken("mname".to_string()).into())
        .and_then(|s| Name::parse(s, origin).map_err(ParseError::from))?;

    let rname: Name = tokens
        .next()
        .ok_or_else(|| ParseErrorKind::MissingToken("rname".to_string()).into())
        .and_then(|s| Name::parse(s, origin).map_err(ParseError::from))?;

    let serial: u32 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("serial".to_string())))
        .and_then(zone::Parser::parse_time)?;

    let refresh: i32 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("refresh".to_string())))
        .and_then(zone::Parser::parse_time)?
        .try_into()
        .map_err(|_e| ParseError::from("refresh outside i32 range"))?;

    let retry: i32 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("retry".to_string())))
        .and_then(zone::Parser::parse_time)?
        .try_into()
        .map_err(|_e| ParseError::from("retry outside i32 range"))?;

    let expire: i32 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("expire".to_string())))
        .and_then(zone::Parser::parse_time)?
        .try_into()
        .map_err(|_e| ParseError::from("expire outside i32 range"))?;

    let minimum: u32 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("minimum".to_string())))
        .and_then(zone::Parser::parse_time)?;

    Ok(SOA::new(
        mname, rname, serial, refresh, retry, expire, minimum,
    ))
}

#[test]
fn test_parse() {
    use core::str::FromStr;

    let soa_tokens = vec![
        "hickory-dns.org.",
        "root.hickory-dns.org.",
        "199609203",
        "8h",
        "120m",
        "7d",
        "24h",
    ];

    let parsed_soa = parse(
        soa_tokens.into_iter(),
        Some(&Name::from_str("example.com.").unwrap()),
    )
    .expect("failed to parse tokens");

    let expected_soa = SOA::new(
        "hickory-dns.org.".parse().unwrap(),
        "root.hickory-dns.org.".parse().unwrap(),
        199609203,
        28800,
        7200,
        604800,
        86400,
    );

    assert_eq!(parsed_soa, expected_soa);
}
