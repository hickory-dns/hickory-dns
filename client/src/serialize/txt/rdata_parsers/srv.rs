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

//! service records for identify port mapping for specific services on a host

use serialize::txt::*;
use error::*;
use rr::domain::Name;
use rr::rdata::SRV;

/// Parse the RData from a set of Tokens
pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<SRV> {
    let mut token = tokens.iter();

    let priority: u16 = try!(
        token
            .next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("priority".to_string()),
            ))
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Ok(try!(s.parse()))
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );
    let weight: u16 = try!(
        token
            .next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("weight".to_string()),
            ))
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Ok(try!(s.parse()))
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );
    let port: u16 = try!(
        token
            .next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("port".to_string()),
            ))
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Ok(try!(s.parse()))
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );
    let target: Name = try!(
        token
            .next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("target".to_string()),
            ))
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Name::parse(s, origin).map_err(ParseError::from)
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );

    Ok(SRV::new(priority, weight, port, target))
}
