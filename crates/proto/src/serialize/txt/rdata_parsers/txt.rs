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

//! text records for storing arbitrary data

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::rr::rdata::TXT;
use crate::serialize::txt::errors::ParseResult;

/// Parse the RData from a set of Tokens
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(tokens: I) -> ParseResult<TXT> {
    let txt_data: Vec<String> = tokens.map(ToString::to_string).collect();
    Ok(TXT::new(txt_data))
}
