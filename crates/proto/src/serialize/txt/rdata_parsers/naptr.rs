// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! naptr records DDDS, RFC 3403

use alloc::string::ToString;
use core::str::FromStr;

use crate::rr::Name;
use crate::rr::rdata::naptr::{NAPTR, verify_flags};
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

/// Parse the RData from a set of Tokens
///
/// ```text
/// ;;      order pflags service           regexp replacement
/// IN NAPTR 100  50  "a"    "z3950+N2L+N2C"     ""   cidserver.example.com.
/// IN NAPTR 100  50  "a"    "rcds+N2C"          ""   cidserver.example.com.
/// IN NAPTR 100  50  "s"    "http+N2L+N2C+N2R"  ""   www.example.com.
/// ```
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(
    mut tokens: I,
    origin: Option<&Name>,
) -> ParseResult<NAPTR> {
    let order: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("order".to_string())))
        .and_then(|s| u16::from_str(s).map_err(Into::into))?;

    let preference: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("preference".to_string())))
        .and_then(|s| u16::from_str(s).map_err(Into::into))?;

    let flags = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("flags".to_string())))
        .map(ToString::to_string)
        .map(|s| s.into_bytes().into_boxed_slice())?;
    if !verify_flags(&flags) {
        return Err(ParseError::from("bad flags, must be in range [a-zA-Z0-9]"));
    }

    let service = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("service".to_string())))
        .map(ToString::to_string)
        .map(|s| s.into_bytes().into_boxed_slice())?;

    let regexp = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("regexp".to_string())))
        .map(ToString::to_string)
        .map(|s| s.into_bytes().into_boxed_slice())?;

    let replacement: Name = tokens
        .next()
        .ok_or_else(|| ParseErrorKind::MissingToken("replacement".to_string()).into())
        .and_then(|s| Name::parse(s, origin).map_err(ParseError::from))?;

    Ok(NAPTR::new(
        order,
        preference,
        flags,
        service,
        regexp,
        replacement,
    ))
}

#[test]
fn test_parsing() {
    // IN NAPTR 100  50  "a"    "z3950+N2L+N2C"     ""   cidserver.example.com.
    // IN NAPTR 100  50  "a"    "rcds+N2C"          ""   cidserver.example.com.
    // IN NAPTR 100  50  "s"    "http+N2L+N2C+N2R"  ""   www.example.com.

    assert_eq!(
        parse(
            vec!["100", "50", "a", "z3950+N2L+N2C", "", "cidserver"].into_iter(),
            Some(&Name::from_str("example.com.").unwrap())
        )
        .expect("failed to parse NAPTR"),
        NAPTR::new(
            100,
            50,
            b"a".to_vec().into_boxed_slice(),
            b"z3950+N2L+N2C".to_vec().into_boxed_slice(),
            b"".to_vec().into_boxed_slice(),
            Name::from_str("cidserver.example.com.").unwrap()
        ),
    );
}

#[test]
fn test_parsing_fails() {
    // IN NAPTR 100  50  "a"    "z3950+N2L+N2C"     ""   cidserver.example.com.
    // IN NAPTR 100  50  "a"    "rcds+N2C"          ""   cidserver.example.com.
    // IN NAPTR 100  50  "s"    "http+N2L+N2C+N2R"  ""   www.example.com.

    assert!(
        parse(
            vec!["100", "50", "-", "z3950+N2L+N2C", "", "cidserver"].into_iter(),
            Some(&Name::from_str("example.com.").unwrap())
        )
        .is_err()
    );
}
