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

use serialize::txt::*;
use error::*;
use rr::domain::Name;
use rr::rdata::MX;

/// Parse the RData from a set of Tokens
pub fn parse(tokens: &Vec<Token>, origin: Option<&Name>) -> ParseResult<MX> {
    let mut token = tokens.iter();

    let preference: u16 = try!(
        token
            .next()
            .ok_or(ParseError::from(
                ParseErrorKind::MissingToken("preference".to_string()),
            ))
            .and_then(|t| if let &Token::CharData(ref s) = t {
                s.parse().map_err(Into::into)
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );
    let exchange: Name = try!(
        token
            .next()
            .ok_or(ParseErrorKind::MissingToken("exchange".to_string()).into())
            .and_then(|t| if let &Token::CharData(ref s) = t {
                Name::parse(s, origin).map_err(ParseError::from)
            } else {
                Err(ParseErrorKind::UnexpectedToken(t.clone()).into())
            })
    );

    Ok(MX::new(preference, exchange))
}
