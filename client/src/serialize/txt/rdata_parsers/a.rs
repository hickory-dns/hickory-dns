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

//! Parser for A text form

use std::net::Ipv4Addr;
use std::str::FromStr;
use error::*;

/// Parse the RData from a set of Tokens
pub fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<Ipv4Addr> {
    let address: Ipv4Addr = tokens
        .next()
        .ok_or_else(|| {
            ParseError::from(ParseErrorKind::MissingToken("ipv4 address".to_string()))
        })
        .and_then(|s| Ipv4Addr::from_str(s).map_err(Into::into))?;
    Ok(address)
}
