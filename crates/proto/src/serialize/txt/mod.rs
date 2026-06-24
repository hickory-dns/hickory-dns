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

use alloc::{string::ToString, vec::Vec};
use core::{
    fmt::{self, Write},
    str::FromStr,
};

mod errors;
pub use errors::{LexerError, ParseError, ParseResult};

#[cfg(feature = "__dnssec")]
pub mod trust_anchor;

#[cfg(feature = "std")]
mod zone;
#[cfg(feature = "std")]
pub use zone::Parser;

mod zone_lex;
pub(crate) use zone_lex::Lexer;
pub use zone_lex::Token;

/// Decodes a `char-string` into the octets it represents.
///
/// [RFC 9460 Appendix A, SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#appendix-A)
///
/// ```text
///   ; non-digit is VCHAR minus DIGIT.
///   non-digit   = %x21-2F / %x3A-7E
///   ; dec-octet is a number 0-255 as a three-digit decimal number.
///   dec-octet   = ( "0" / "1" ) 2DIGIT /
///                 "2" ( ( %x30-34 DIGIT ) / ( "5" %x30-35 ) )
///   escaped     = "\" ( non-digit / dec-octet )
/// ```
pub fn decode_char_string(value: &str) -> Result<Vec<u8>, ParseError> {
    let mut bytes = value.bytes();
    let mut value = Vec::with_capacity(value.len());

    while let Some(byte) = bytes.next() {
        let b'\\' = byte else {
            value.push(byte);
            continue;
        };

        match bytes.next() {
            Some(d1 @ b'0'..=b'9') => {
                let (Some(d2 @ b'0'..=b'9'), Some(d3 @ b'0'..=b'9')) = (bytes.next(), bytes.next())
                else {
                    return Err(ParseError::Message(
                        "expected three decimal digits after '\\'",
                    ));
                };

                #[allow(clippy::identity_op)]
                let octet = 100 * u16::from(d1 - b'0')
                    + 10 * u16::from(d2 - b'0')
                    + 1 * u16::from(d3 - b'0');

                if octet > 255 {
                    return Err(ParseError::Message("dec-octet must be in range 0-255"));
                }

                value.push(octet as u8);
            }
            Some(byte) => value.push(byte),
            None => return Err(ParseError::Message("unterminated escape sequence")),
        }
    }

    Ok(value)
}

/// Encodes octets as a quoted `char-string`.
pub fn encode_char_string<W: Write>(value: &[u8], f: &mut W) -> Result<(), fmt::Error> {
    f.write_char('"')?;
    for byte in value.iter().copied() {
        match byte {
            b'"' | b'\\' => {
                f.write_char('\\')?;
                f.write_char(byte as char)?;
            }
            b' '..=b'~' => f.write_char(byte as char)?,
            #[expect(clippy::identity_op)]
            _ => {
                f.write_char('\\')?;
                f.write_char(char::from(b'0' + byte / 100 % 10))?;
                f.write_char(char::from(b'0' + byte / 10 % 10))?;
                f.write_char(char::from(b'0' + byte / 1 % 10))?;
            }
        }
    }
    f.write_char('"')
}

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
/// use hickory_proto::serialize::txt::parse_ttl;
///
/// assert_eq!(parse_ttl("0").unwrap(),  0);
/// assert!(parse_ttl("s").is_err());
/// assert!(parse_ttl("").is_err());
/// assert_eq!(parse_ttl("0s").unwrap(), 0);
/// assert_eq!(parse_ttl("1").unwrap(),  1);
/// assert_eq!(parse_ttl("1S").unwrap(), 1);
/// assert_eq!(parse_ttl("1s").unwrap(), 1);
/// assert_eq!(parse_ttl("1M").unwrap(), 60);
/// assert_eq!(parse_ttl("1m").unwrap(), 60);
/// assert_eq!(parse_ttl("1H").unwrap(), 3600);
/// assert_eq!(parse_ttl("1h").unwrap(), 3600);
/// assert_eq!(parse_ttl("1D").unwrap(), 86400);
/// assert_eq!(parse_ttl("1d").unwrap(), 86400);
/// assert_eq!(parse_ttl("1W").unwrap(), 604800);
/// assert_eq!(parse_ttl("1w").unwrap(), 604800);
/// assert_eq!(parse_ttl("1s2d3w4h2m").unwrap(), 1+2*86400+3*604800+4*3600+2*60);
/// assert_eq!(parse_ttl("3w3w").unwrap(), 3*604800+3*604800);
/// assert!(parse_ttl("7102w").is_err());
/// ```
pub fn parse_ttl(ttl_str: &str) -> ParseResult<u32> {
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

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use super::*;

    fn encode(bytes: &[u8]) -> String {
        let mut string = String::new();
        encode_char_string(bytes, &mut string).unwrap();
        string
    }

    #[test]
    fn decode_passthrough() {
        assert_eq!(decode_char_string("").unwrap(), b"");
        assert_eq!(decode_char_string("hello").unwrap(), b"hello");
        assert_eq!(decode_char_string("fizz, buzz").unwrap(), b"fizz, buzz");
        // non-ASCII octets pass through unchanged
        assert_eq!(decode_char_string("héllo").unwrap(), "héllo".as_bytes());
    }

    /// [RFC 9460 Appendix A, SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#appendix-A)
    ///
    /// ```text
    ///   escaped     = "\" ( non-digit / dec-octet )
    /// ```
    #[test]
    fn decode_escaped() {
        // "\" non-digit
        assert_eq!(decode_char_string(r#"\\"#).unwrap(), b"\\");
        assert_eq!(decode_char_string(r#"\""#).unwrap(), b"\"");
        assert_eq!(decode_char_string(r#"a\;b"#).unwrap(), b"a;b");
        // "\" dec-octet, full range
        assert_eq!(decode_char_string(r#"\000"#).unwrap(), b"\x00");
        assert_eq!(decode_char_string(r#"\255"#).unwrap(), b"\xff");
        // RFC 4343 §2.1: '.' can be expressed as \046 or \.
        assert_eq!(decode_char_string(r#"\046"#).unwrap(), b".");
        assert_eq!(decode_char_string(r#"\."#).unwrap(), b".");
    }

    /// [RFC 9460 Appendix D, SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#appendix-D)
    ///
    /// Figure 6: A Generic Key and Quoted Value with a Decimal Escape, and
    /// Figure 10: An "alpn" Value with an Escaped Comma and an Escaped
    /// Backslash in Two Presentation Formats
    #[test]
    fn decode_rfc9460_appendix_d_vectors() {
        // Figure 6: \210 is the single octet 0xD2
        assert_eq!(
            decode_char_string(r#"hello\210qoo"#).unwrap(),
            b"hello\xd2qoo"
        );

        // Figure 10: the quoted and contiguous forms decode to the same value
        assert_eq!(
            decode_char_string(r#"f\\\\oo\\,bar,h2"#).unwrap(),
            b"f\\\\oo\\,bar,h2"
        );
        assert_eq!(
            decode_char_string(r#"f\\\092oo\092,bar,h2"#).unwrap(),
            b"f\\\\oo\\,bar,h2"
        );
    }

    /// [RFC 9460 Appendix A.1, SVCB and HTTPS Resource Records, Nov 2023](https://datatracker.ietf.org/doc/html/rfc9460#appendix-A.1)
    ///
    /// ```text
    ///   Decoding of value-lists happens after character-string decoding.  For
    ///   example, consider these char-string SvcParamValues:
    ///
    ///   "part1,part2,part3\\,part4\\\\"
    ///   part1\,\p\a\r\t2\044part3\092,part4\092\\
    ///
    ///   These inputs are equivalent: character-string decoding either of them
    ///   would produce the same value:
    ///
    ///   part1,part2,part3\,part4\\
    /// ```
    #[test]
    fn decode_rfc9460_appendix_a1_equivalence() {
        let expected = b"part1,part2,part3\\,part4\\\\";

        assert_eq!(
            decode_char_string(r#"part1,part2,part3\\,part4\\\\"#).unwrap(),
            expected
        );
        assert_eq!(
            decode_char_string(r#"part1\,\p\a\r\t2\044part3\092,part4\092\\"#).unwrap(),
            expected
        );
    }

    #[test]
    fn decode_invalid() {
        // dangling escape
        assert!(decode_char_string(r#"\"#).is_err());
        // a digit after '\' must be followed by exactly two more digits
        assert!(decode_char_string(r#"\2"#).is_err());
        assert!(decode_char_string(r#"\26"#).is_err());
        assert!(decode_char_string(r#"\2a6"#).is_err());
        // dec-octet must be 0-255
        assert!(decode_char_string(r#"\256"#).is_err());
        assert!(decode_char_string(r#"\999"#).is_err());
    }

    #[test]
    fn encode_basics() {
        assert_eq!(encode(b""), r#""""#);
        assert_eq!(encode(b"hello"), r#""hello""#);
        // whitespace needs no escaping inside the quotes
        assert_eq!(encode(b"fizz, buzz"), r#""fizz, buzz""#);
        // '"' and '\' are escaped as \X
        assert_eq!(encode(b"a\"b"), r#""a\"b""#);
        assert_eq!(encode(b"a\\b"), r#""a\\b""#);
        // octets outside %x20-7E are escaped as \DDD
        assert_eq!(encode(b"\x00\x09\x7f\xff"), r#""\000\009\127\255""#);
        // Figure 6's value encodes back to its quoted presentation
        assert_eq!(encode(b"hello\xd2qoo"), r#""hello\210qoo""#);
    }

    #[test]
    fn round_trip_all_octets() {
        let decoded = (0..=255).collect::<Vec<u8>>();

        let encoded = encode(&decoded);
        let encoded = encoded
            .strip_prefix('"')
            .unwrap()
            .strip_suffix('"')
            .unwrap();

        assert_eq!(decode_char_string(encoded).unwrap(), decoded);
    }
}
