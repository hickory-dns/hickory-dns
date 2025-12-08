// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use alloc::boxed::Box;
use alloc::string::String;
#[cfg(feature = "wasm-bindgen")]
use alloc::string::ToString;
#[cfg(target_os = "android")]
use alloc::sync::Arc;
use core::num::ParseIntError;

use thiserror::Error;

use crate::op::Header;
use crate::serialize::binary::DecodeError;

/// An alias for results returned by functions of this crate
pub(crate) type ProtoResult<T> = ::core::result::Result<T, ProtoError>;

/// The error kind for errors that get returned in the crate
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// Character data length exceeded the limit
    #[non_exhaustive]
    #[error("char data length exceeds {max}: {len}")]
    CharacterDataTooLong {
        /// Specified maximum
        max: usize,
        /// Actual length
        len: usize,
    },

    /// Crypto operation failed
    #[error("crypto error: {0}")]
    #[cfg(feature = "__dnssec")]
    Crypto(&'static str),

    /// Message decoding error
    #[error("decoding error: {0}")]
    Decode(#[from] DecodeError),

    /// Format error in Message Parsing
    #[error("message format error: {error}")]
    FormError {
        /// Header of the bad Message
        header: Header,
        /// Error that occurred while parsing the Message
        error: Box<Self>,
    },

    /// The maximum buffer size was exceeded
    #[error("maximum buffer size exceeded: {0}")]
    MaxBufferSizeExceeded(usize),

    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Not all records were able to be written
    #[non_exhaustive]
    #[error("not all records could be written, wrote: {count}")]
    NotAllRecordsWritten {
        /// Number of records that were written before the error
        count: usize,
    },

    /// An url parsing error
    #[error("url parsing error")]
    UrlParsing(#[from] url::ParseError),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    Utf8(#[from] core::str::Utf8Error),

    /// A utf8 parsing error
    #[error("error parsing utf8 string")]
    FromUtf8(#[from] alloc::string::FromUtf8Error),

    /// An int parsing error
    #[error("error parsing int")]
    ParseInt(#[from] ParseIntError),

    /// A JNI call error
    #[cfg(target_os = "android")]
    #[error("JNI call error: {0}")]
    Jni(Arc<jni::errors::Error>),
}

impl From<String> for ProtoError {
    fn from(msg: String) -> Self {
        Self::Msg(msg)
    }
}

impl From<&'static str> for ProtoError {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg)
    }
}

#[cfg(target_os = "android")]
impl From<jni::errors::Error> for ProtoError {
    fn from(e: jni::errors::Error) -> Self {
        ProtoError::Jni(Arc::new(e))
    }
}

#[cfg(feature = "wasm-bindgen")]
impl From<ProtoError> for wasm_bindgen_crate::JsValue {
    fn from(e: ProtoError) -> Self {
        js_sys::Error::new(&e.to_string()).into()
    }
}
