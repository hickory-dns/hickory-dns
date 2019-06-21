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

//! Dnssec error types for the crate

use std::fmt;

use failure::{Backtrace, Context, Fail};

#[cfg(not(feature = "openssl"))]
use self::not_openssl::SslErrorStack;
#[cfg(not(feature = "ring"))]
use self::not_ring::{KeyRejected, Unspecified};
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(feature = "ring")]
use ring::error::{KeyRejected, Unspecified};
use proto::error::{ProtoError, ProtoErrorKind};

/// An alias for dnssec results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for dnssec errors that get returned in the crate
#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[fail(display = "{}", _0)]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[fail(display = "{}", _0)]
    Msg(String),

    // foreign
    /// An error got returned by the trust-dns-proto crate
    #[fail(display = "proto error")]
    Proto,

    /// A ring error
    #[fail(display = "ring error")]
    Ring,

    /// An ssl error
    #[fail(display = "ssl error")]
    SSL,

    /// A request timed out
    #[fail(display = "request timed out")]
    Timeout,
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match *self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),

            // foreign
            Proto => Proto,
            Ring => Ring,
            SSL => SSL,
            Timeout => Timeout,
        }
    }
}

/// The error type for dnssec errors that get returned in the crate
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    /// Get the kind of the error
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Error {
        ErrorKind::Message(msg).into()
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        ErrorKind::Msg(msg).into()
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Error {
        match *e.kind() {
            ProtoErrorKind::Timeout => e.context(ErrorKind::Timeout).into(),
            _ => e.context(ErrorKind::Proto).into(),
        }
    }
}

impl From<KeyRejected> for Error {
    fn from(e: KeyRejected) -> Error {
        e.context(ErrorKind::Ring).into()
    }
}

impl From<Unspecified> for Error {
    fn from(e: Unspecified) -> Error {
        e.context(ErrorKind::Ring).into()
    }
}

impl From<SslErrorStack> for Error {
    fn from(e: SslErrorStack) -> Error {
        e.context(ErrorKind::SSL).into()
    }
}

#[cfg(not(feature = "openssl"))]
pub mod not_openssl {
    use std;

    #[derive(Debug)]
    pub struct SslErrorStack;

    impl std::fmt::Display for SslErrorStack {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for SslErrorStack {
        fn description(&self) -> &str {
            "openssl feature not enabled"
        }
    }
}

#[cfg(not(feature = "ring"))]
pub mod not_ring {
    use std;

    #[derive(Debug)]
    pub struct KeyRejected;

    #[derive(Debug)]
    pub struct Unspecified;

    impl std::fmt::Display for KeyRejected {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for KeyRejected {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }

    impl std::fmt::Display for Unspecified {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for Unspecified {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }
}
