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

//! text records for storing arbitrary data

use serialize::txt::*;
use error::*;
use rr::rdata::TXT;

/// Parse the RData from a set of Tokens
pub fn parse(tokens: &Vec<Token>) -> ParseResult<TXT> {
    let mut txt_data: Vec<String> = Vec::with_capacity(tokens.len());
    for t in tokens {
        match *t {
            Token::CharData(ref txt) => txt_data.push(txt.clone()),
            _ => return Err(ParseErrorKind::UnexpectedToken(t.clone()).into()),
        }
    }

    Ok(TXT::new(txt_data))
}
