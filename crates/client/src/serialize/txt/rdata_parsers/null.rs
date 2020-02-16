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

//! null record type, generally not used except as an internal tool for representing null data

use crate::error::*;
use crate::rr::rdata::NULL;

/// Parse the RData from a set of Tokens
#[allow(unused)]
pub fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<NULL> {
    Err(ParseError::from(ParseErrorKind::Msg(
        "Parse is not implemented for NULL record".to_string(),
    )))
}
