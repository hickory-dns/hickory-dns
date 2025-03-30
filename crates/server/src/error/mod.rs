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
#[cfg(feature = "backtrace")]
use crate::proto::{ExtBacktrace, trace};
use crate::proto::{ProtoError, ProtoErrorKind};

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PersistenceErrorKind {
    /// An error that occurred when recovering from journal
    #[error("error recovering from journal: {}", _0)]
    Recovery(&'static str),

    /// The number of inserted records didn't match the expected amount
    #[error("wrong insert count: {} expect: {}", got, expect)]
    WrongInsertCount {
        /// The number of inserted records
        got: usize,
        /// The number of records expected to be inserted
        expect: usize,
    },

    // foreign
    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// An error got returned from the sqlite crate
    #[cfg(feature = "sqlite")]
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A request timed out
    #[error("request timed out")]
    Timeout,
}

/// The error type for errors that get returned in the crate
#[derive(Debug, Error)]
pub struct PersistenceError {
    kind: PersistenceErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl PersistenceError {
    /// Get the kind of the error
    pub fn kind(&self) -> &PersistenceErrorKind {
        &self.kind
    }
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(backtrace) = &self.backtrack {
                    fmt::Display::fmt(&self.kind, f)?;
                    fmt::Debug::fmt(backtrace, f)
                } else {
                    fmt::Display::fmt(&self.kind, f)
                }
            } else {
                fmt::Display::fmt(&self.kind, f)
            }
        }
    }
}

impl From<PersistenceErrorKind> for PersistenceError {
    fn from(kind: PersistenceErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<ProtoError> for PersistenceError {
    fn from(e: ProtoError) -> Self {
        match e.kind() {
            ProtoErrorKind::Timeout => PersistenceErrorKind::Timeout.into(),
            _ => PersistenceErrorKind::from(e).into(),
        }
    }
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for PersistenceError {
    fn from(e: rusqlite::Error) -> Self {
        PersistenceErrorKind::from(e).into()
    }
}

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
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl ConfigError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ConfigErrorKind {
        &self.kind
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(backtrace) = &self.backtrack {
                    fmt::Display::fmt(&self.kind, f)?;
                    fmt::Debug::fmt(backtrace, f)
                } else {
                    fmt::Display::fmt(&self.kind, f)
                }
            } else {
                fmt::Display::fmt(&self.kind, f)
            }
        }
    }
}

impl<E> From<E> for ConfigError
where
    E: Into<ConfigErrorKind>,
{
    fn from(error: E) -> Self {
        let kind: ConfigErrorKind = error.into();

        Self {
            kind: Box::new(kind),
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}
