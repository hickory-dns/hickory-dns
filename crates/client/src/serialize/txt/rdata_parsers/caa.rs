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

//! mail exchange, email, record

use tracing::warn;

use crate::proto::rr::rdata::caa;
use crate::proto::rr::rdata::caa::{Property, Value};

use crate::error::*;
use crate::rr::rdata::CAA;

/// Parse the RData from a set of Tokens
///
/// [RFC 6844, DNS Certification Authority Authorization, January 2013](https://tools.ietf.org/html/rfc6844#section-5.1)
///
/// ```text
/// 5.1.1.  Canonical Presentation Format
///
///    The canonical presentation format of the CAA record is:
///
///    CAA <flags> <tag> <value>
///
///    Where:
///
///    Flags:  Is an unsigned integer between 0 and 255.
///
///    Tag:  Is a non-zero sequence of US-ASCII letters and numbers in lower
///       case.
///
///    Value:  Is the <character-string> encoding of the value field as
///       specified in [RFC1035], Section 5.1.
/// ```
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<CAA> {
    let flags_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("caa flags not present")))?;
    let tag_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("caa tag not present")))?;
    let value_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("caa value not present")))?;

    // parse the flags
    let issuer_critical = {
        let flags = flags_str.parse::<u8>()?;
        if flags & 0b0111_1111 != 0 {
            warn!("unexpected flag values in caa (0 or 128): {}", flags);
        }

        flags & 0b1000_0000 != 0
    };

    // parse the tag
    let tag = {
        // unnecessary clone
        let tag = Property::from(tag_str.to_string());
        if tag.is_unknown() {
            warn!("unknown tag found for caa: {:?}", tag);
        }
        tag
    };

    // parse the value
    let value = {
        // TODO: this is a slight dup of the match logic in caa::read_value(..)
        match tag {
            Property::Issue | Property::IssueWild => {
                let value = caa::read_issuer(value_str.as_bytes())?;
                Value::Issuer(value.0, value.1)
            }
            Property::Iodef => {
                let url = caa::read_iodef(value_str.as_bytes())?;
                Value::Url(url)
            }
            Property::Unknown(_) => Value::Unknown(value_str.as_bytes().to_vec()),
        }
    };

    // return the new CAA record
    Ok(CAA {
        issuer_critical,
        tag,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing() {
        //nocerts       CAA 0 issue \";\"
        assert!(parse(vec!["0", "issue", ";"].into_iter()).is_ok());
        // certs         CAA 0 issuewild \"example.net\"
        assert!(parse(vec!["0", "issue", "example.net"].into_iter()).is_ok());
    }
}
