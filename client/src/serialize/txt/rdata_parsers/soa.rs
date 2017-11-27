/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Parser for SOA text form
use std::str::FromStr;

use error::*;
use rr::domain::Name;
use rr::rdata::SOA;

/// Parse the RData from a set of Tokens
pub fn parse<'i, I: Iterator<Item = &'i str>>(
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
        .ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken("serial".to_string()))
        })
        .and_then(|s| u32::from_str(s).map_err(Into::into))?;

    let refresh: i32 = tokens
        .next()
        .ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken("refresh".to_string()))
        })
        .and_then(|s| i32::from_str(s).map_err(Into::into))?;

    let retry: i32 = tokens
        .next()
        .ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken("retry".to_string()))
        })
        .and_then(|s| i32::from_str(s).map_err(Into::into))?;

    let expire: i32 = tokens
        .next()
        .ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken("expire".to_string()))
        })
        .and_then(|s| i32::from_str(s).map_err(Into::into))?;

    let minimum: u32 = tokens
        .next()
        .ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken("minimum".to_string()))
        })
        .and_then(|s| u32::from_str(s).map_err(Into::into))?;

    Ok(SOA::new(
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    ))
}
