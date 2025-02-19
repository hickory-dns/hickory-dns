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

//! service records for identify port mapping for specific services on a host
use alloc::string::ToString;
use core::str::FromStr;

use crate::rr::domain::Name;
use crate::rr::rdata::SRV;
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

/// Parse the RData from a set of Tokens
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(
    mut tokens: I,
    origin: Option<&Name>,
) -> ParseResult<SRV> {
    let priority: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("priority".to_string())))
        .and_then(|s| u16::from_str(s).map_err(Into::into))?;

    let weight: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("weight".to_string())))
        .and_then(|s| u16::from_str(s).map_err(Into::into))?;

    let port: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("port".to_string())))
        .and_then(|s| u16::from_str(s).map_err(Into::into))?;

    let target: Name = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("target".to_string())))
        .and_then(|s| Name::parse(s, origin).map_err(ParseError::from))?;

    Ok(SRV::new(priority, weight, port, target))
}
