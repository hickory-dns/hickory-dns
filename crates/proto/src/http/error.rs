// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::string::String;
use core::num::ParseIntError;
use std::io;

use crate::error::ProtoError;
use http::header::ToStrError;
use thiserror::Error;

/// An alias for results returned by functions of this crate
pub type Result<T> = ::core::result::Result<T, Error>;

/// Internal HTTP error type
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Unable to decode header value to string
    #[error("header decode error: {0}")]
    Decode(#[from] ToStrError),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Unable to parse header value as number
    #[error("unable to parse number: {0}")]
    ParseInt(#[from] ParseIntError),

    /// A proto error
    #[error("proto error: {0}")]
    ProtoError(#[from] ProtoError),

    /// An HTTP/2 related error
    #[error("H2: {0}")]
    #[cfg(feature = "__https")]
    H2(#[from] h2::Error),

    /// An HTTP/3 related error
    #[error("H3: {0}")]
    #[cfg(feature = "__h3")]
    H3(#[from] h3::error::StreamError),
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg)
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Self::Msg(msg)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        Self::other(format!("https: {err}"))
    }
}
