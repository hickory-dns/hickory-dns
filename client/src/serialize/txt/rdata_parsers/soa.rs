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

use serialize::txt::*;
use error::*;
use rr::domain::Name;
use rr::rdata::SOA;

/// Parse the RData from a set of Tokens
pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<SOA> {
    let mut token = tokens.iter();

    let mname: Name = try!(
        token
            .next()
            .ok_or(ParseErrorKind::MissingToken("mname".to_string()).into())
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Name::parse(s, origin).map_err(ParseError::from)
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );
    let rname: Name = try!(
        token
            .next()
            .ok_or(ParseErrorKind::MissingToken("rname".to_string()).into())
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Name::parse(s, origin).map_err(ParseError::from)
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );
    let mut list = try!(
        token
            .next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("List".to_string()),
            ))
            .and_then(|t| if let &Token::List(ref v) = t {
                Ok(v)
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    ).iter();

    let serial: u32 = try!(
        list.next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("serial".to_string()),
            ))
            .and_then(|s| Ok(try!(s.parse())))
    );
    let refresh: i32 = try!(
        list.next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("refresh".to_string()),
            ))
            .and_then(|s| Ok(try!(s.parse())))
    );
    let retry: i32 = try!(
        list.next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("retry".to_string()),
            ))
            .and_then(|s| Ok(try!(s.parse())))
    );
    let expire: i32 = try!(
        list.next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("expire".to_string()),
            ))
            .and_then(|s| Ok(try!(s.parse())))
    );
    let minimum: u32 = try!(
        list.next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("minimum".to_string()),
            ))
            .and_then(|s| Ok(try!(s.parse())))
    );

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
