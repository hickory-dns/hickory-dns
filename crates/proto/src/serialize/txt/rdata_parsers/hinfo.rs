// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HINFO record for storing host information

use alloc::string::ToString;

use crate::rr::rdata::HINFO;
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

/// Parse the RData from a set of Tokens
///
/// ```text
/// IN HINFO DEC-2060 TOPS20
/// IN HINFO VAX-11/780 UNIX
/// ```
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<HINFO> {
    let cpu = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("cpu".to_string())))
        .map(ToString::to_string)?;
    let os = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("os".to_string())))
        .map(ToString::to_string)?;
    Ok(HINFO::new(cpu, os))
}

#[test]
fn test_parsing() {
    // IN HINFO DEC-2060 TOPS20

    assert_eq!(
        parse(vec!["DEC-2060", "TOPS20"].into_iter()).expect("failed to parse NAPTR"),
        HINFO::new("DEC-2060".to_string(), "TOPS20".to_string()),
    );
}

#[test]
fn test_parsing_fails() {
    // IN HINFO DEC-2060 TOPS20

    assert!(parse(vec!["DEC-2060"].into_iter()).is_err());
    assert!(parse(vec![].into_iter()).is_err());
}
