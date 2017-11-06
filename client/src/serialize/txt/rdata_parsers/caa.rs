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

use trust_dns_proto::rr::rdata::caa;
use trust_dns_proto::rr::rdata::caa::{Property, Value};

use serialize::txt::*;
use error::*;
use rr::domain::Name;
use rr::rdata::CAA;

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
pub fn parse(tokens: &Vec<Token>, _origin: Option<&Name>) -> ParseResult<CAA> {
    let mut iter = tokens.iter();

    let flags: &Token = iter.next().ok_or_else(
        || ParseError::from(ParseErrorKind::Message("caa flags not present")),
    )?;
    let tag: &Token = iter.next().ok_or_else(
        || ParseError::from(ParseErrorKind::Message("caa tag not present")),
    )?;
    let value: &Token = iter.next().ok_or_else(
        || ParseError::from(ParseErrorKind::Message("caa value not present")),
    )?;

    // parse the flags
    let issuer_critical = if let Token::CharData(ref flags_str) = *flags {
        let flags = u8::from_str_radix(flags_str, 10)?;
        if flags & 0b0111_1111 != 0 {
            warn!("unexpected flag values in caa (0 or 128): {}", flags);
        }

        flags & 0b1000_0000 != 0
    } else {
        return Err(
            ParseErrorKind::Msg(format!("unexpected token for caa flags: {:?}", flags)).into(),
        );
    };

    // parse the tag
    let tag = if let Token::CharData(ref tag_str) = *tag {
        // unnecessary clone
        let tag = Property::from(tag_str.to_string());
        if tag.is_unknown() {
            warn!("unknown tag found for caa: {:?}", tag);
        }
        tag
    } else {
        return Err(
            ParseErrorKind::Msg(format!("unexpected token for caa tag: {:?}", tag)).into(),
        );
    };

    // parse the value
    let value = if let Token::CharData(ref value_str) = *value {
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
    } else {
        return Err(
            ParseErrorKind::Msg(format!("unexpected token for caa value: {:?}", value)).into(),
        );
    };

    // return the new CAA record
    Ok(CAA {
        issuer_critical,
        tag,
        value,
    })
}
