// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CSYNC record for synchronizing information to the parent zone

use alloc::string::ToString;
use alloc::vec::Vec;
use core::str::FromStr;

use crate::rr::RecordType;
use crate::rr::rdata::CSYNC;
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

/// Parse the RData from a set of Tokens
///
/// ```text
/// IN CSYNC 1 3 A NS AAAA
/// IN CSYNC 66 0 MX
/// ```
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<CSYNC> {
    let soa_serial: u32 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("soa_serial".to_string())))
        .and_then(|s| s.parse().map_err(Into::into))?;

    let flags: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("flags".to_string())))
        .and_then(|s| s.parse().map_err(Into::into))?;

    let immediate: bool = flags & 0b0000_0001 == 0b0000_0001;
    let soa_minimum: bool = flags & 0b0000_0010 == 0b0000_0010;

    let mut record_types: Vec<RecordType> = Vec::new();

    for token in tokens {
        let record_type: RecordType = RecordType::from_str(token)?;
        record_types.push(record_type);
    }

    Ok(CSYNC::new(soa_serial, immediate, soa_minimum, record_types))
}

#[test]
fn test_parsing() {
    // IN CSYNC 123 3 NS

    assert_eq!(
        parse(vec!["123", "3", "NS"].into_iter()).expect("failed to parse CSYNC"),
        CSYNC::new(123, true, true, vec![RecordType::NS]),
    );
}

#[test]
fn test_parsing_fails() {
    // IN CSYNC NS

    assert!(parse(vec!["NS"].into_iter()).is_err());
    assert!(parse(vec![].into_iter()).is_err());
}
