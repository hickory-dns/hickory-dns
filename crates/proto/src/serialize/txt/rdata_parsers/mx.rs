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

//! mail exchange, email, record

use alloc::string::ToString;

use crate::rr::domain::Name;
use crate::rr::rdata::MX;
use crate::serialize::txt::errors::{ParseError, ParseErrorKind, ParseResult};

/// Parse the RData from a set of Tokens
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(
    mut tokens: I,
    origin: Option<&Name>,
) -> ParseResult<MX> {
    let preference: u16 = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::MissingToken("preference".to_string())))
        .and_then(|s| s.parse().map_err(Into::into))?;
    let exchange: Name = tokens
        .next()
        .ok_or_else(|| ParseErrorKind::MissingToken("exchange".to_string()).into())
        .and_then(|s| Name::parse(s, origin).map_err(ParseError::from))?;

    Ok(MX::new(preference, exchange))
}
