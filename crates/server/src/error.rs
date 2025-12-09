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

//! All defined errors for Hickory DNS

use std::{fmt, io};

use thiserror::Error;

use crate::proto::serialize::txt::ParseError;

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigErrorKind {
    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// An error occurred while decoding toml data
    #[cfg(feature = "toml")]
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),

    /// An error occurred while parsing a zone file
    #[error("failed to parse the zone file: {0}")]
    ZoneParse(#[from] ParseError),
}

/// The error type for errors that get returned in the crate
#[derive(Debug)]
pub struct ConfigError {
    kind: Box<ConfigErrorKind>,
}

impl ConfigError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ConfigErrorKind {
        &self.kind
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.kind))
    }
}

impl<E> From<E> for ConfigError
where
    E: Into<ConfigErrorKind>,
{
    fn from(error: E) -> Self {
        Self {
            kind: Box::new(error.into()),
        }
    }
}
