// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{fmt, io};

use thiserror::Error;

use crate::proto::serialize::txt::ParseError;
#[cfg(feature = "backtrace")]
use crate::proto::{ExtBacktrace, trace};

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
