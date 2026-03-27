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

//! Text serialization types

use alloc::string::ToString;
use core::str::FromStr;

mod errors;
mod parse_rdata;
mod rdata_parsers;
#[cfg(feature = "__dnssec")]
pub mod trust_anchor;
mod zone;
mod zone_lex;

pub use self::parse_rdata::RDataParser;
pub use self::zone::Parser;
use self::zone_lex::Lexer;
pub use self::zone_lex::Token;
pub use errors::{LexerError, ParseError, ParseResult};

/// parses the string following the rules from:
///  <https://tools.ietf.org/html/rfc2308> (NXCaching RFC) and
///  <https://www.zytrax.com/books/dns/apa/time.html>
///
/// default is seconds
/// #s = seconds = # x 1 seconds (really!)
/// #m = minutes = # x 60 seconds
/// #h = hours   = # x 3600 seconds
/// #d = day     = # x 86400 seconds
/// #w = week    = # x 604800 seconds
///
/// returns the result of the parsing or and error
///
/// # Example
/// ```
/// use hickory_proto::serialize::txt::parse_time;
///
/// assert_eq!(parse_time("0").unwrap(),  0);
/// assert!(parse_time("s").is_err());
/// assert!(parse_time("").is_err());
/// assert_eq!(parse_time("0s").unwrap(), 0);
/// assert_eq!(parse_time("1").unwrap(),  1);
/// assert_eq!(parse_time("1S").unwrap(), 1);
/// assert_eq!(parse_time("1s").unwrap(), 1);
/// assert_eq!(parse_time("1M").unwrap(), 60);
/// assert_eq!(parse_time("1m").unwrap(), 60);
/// assert_eq!(parse_time("1H").unwrap(), 3600);
/// assert_eq!(parse_time("1h").unwrap(), 3600);
/// assert_eq!(parse_time("1D").unwrap(), 86400);
/// assert_eq!(parse_time("1d").unwrap(), 86400);
/// assert_eq!(parse_time("1W").unwrap(), 604800);
/// assert_eq!(parse_time("1w").unwrap(), 604800);
/// assert_eq!(parse_time("1s2d3w4h2m").unwrap(), 1+2*86400+3*604800+4*3600+2*60);
/// assert_eq!(parse_time("3w3w").unwrap(), 3*604800+3*604800);
/// assert!(parse_time("7102w").is_err());
/// ```
pub fn parse_time(ttl_str: &str) -> ParseResult<u32> {
    if ttl_str.is_empty() {
        return Err(ParseError::ParseTime(ttl_str.to_string()));
    }

    let (mut state, mut value) = (None, 0_u32);
    for (i, c) in ttl_str.char_indices() {
        let start = match (state, c) {
            (None, '0'..='9') => {
                state = Some(i);
                continue;
            }
            (Some(_), '0'..='9') => continue,
            (Some(start), 'S' | 's' | 'M' | 'm' | 'H' | 'h' | 'D' | 'd' | 'W' | 'w') => start,
            _ => return Err(ParseError::ParseTime(ttl_str.to_string())),
        };

        // All allowed chars are ASCII, so using char indexes to slice &[u8] is OK
        let number = u32::from_str(&ttl_str[start..i])
            .map_err(|_| ParseError::ParseTime(ttl_str.to_string()))?;

        let multiplier = match c {
            'S' | 's' => 1,
            'M' | 'm' => 60,
            'H' | 'h' => 3_600,
            'D' | 'd' => 86_400,
            'W' | 'w' => 604_800,
            _ => unreachable!(),
        };

        value = number
            .checked_mul(multiplier)
            .and_then(|add| value.checked_add(add))
            .ok_or_else(|| ParseError::ParseTime(ttl_str.to_string()))?;

        state = None;
    }

    if let Some(start) = state {
        // All allowed chars are ASCII, so using char indexes to slice &[u8] is OK
        let number = u32::from_str(&ttl_str[start..])
            .map_err(|_| ParseError::ParseTime(ttl_str.to_string()))?;
        value = value
            .checked_add(number)
            .ok_or_else(|| ParseError::ParseTime(ttl_str.to_string()))?;
    }

    Ok(value)
}
