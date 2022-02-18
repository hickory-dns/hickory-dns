// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Dnssec error types for the crate

use std::fmt;

#[cfg(not(feature = "openssl"))]
use self::not_openssl::SslErrorStack;
#[cfg(not(feature = "ring"))]
use self::not_ring::{KeyRejected, Unspecified};
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(feature = "ring")]
use ring::error::{KeyRejected, Unspecified};
use thiserror::Error;
use trust_dns_proto::error::{ProtoError, ProtoErrorKind};

#[cfg(feature = "backtrace")]
use crate::proto::{trace, ExtBacktrace};

/// An alias for dnssec results returned by functions of this crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// The error kind for dnssec errors that get returned in the crate
#[allow(unreachable_pub)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    // foreign
    /// An error got returned by the trust-dns-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// A ring error
    #[error("ring error: {0}")]
    RingKeyRejected(#[from] KeyRejected),

    /// A ring error
    #[error("ring error: {0}")]
    RingUnspecified(#[from] Unspecified),

    /// An ssl error
    #[error("ssl error: {0}")]
    SSL(#[from] SslErrorStack),

    /// A request timed out
    #[error("request timed out")]
    Timeout,
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),

            // foreign
            Proto(proto) => Proto(proto.clone()),
            RingKeyRejected(r) => Msg(format!("Ring rejected key: {}", r)),
            RingUnspecified(_r) => RingUnspecified(Unspecified),
            SSL(ssl) => Msg(format!("SSL had an error: {}", ssl)),
            Timeout => Timeout,
        }
    }
}

/// The error type for dnssec errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct Error {
    kind: ErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl Error {
    /// Get the kind of the error
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cfg_if::cfg_if! {
            if #[cfg(feature = "backtrace")] {
                if let Some(ref backtrace) = self.backtrack {
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

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Self {
        ErrorKind::Message(msg).into()
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        ErrorKind::Msg(msg).into()
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Self {
        match *e.kind() {
            ProtoErrorKind::Timeout => ErrorKind::Timeout.into(),
            _ => ErrorKind::from(e).into(),
        }
    }
}

impl From<KeyRejected> for Error {
    fn from(e: KeyRejected) -> Self {
        ErrorKind::from(e).into()
    }
}

impl From<Unspecified> for Error {
    fn from(e: Unspecified) -> Self {
        ErrorKind::from(e).into()
    }
}

impl From<SslErrorStack> for Error {
    fn from(e: SslErrorStack) -> Self {
        ErrorKind::from(e).into()
    }
}

#[allow(unreachable_pub)]
#[cfg(not(feature = "openssl"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "openssl"))))]
pub mod not_openssl {
    use std;

    #[derive(Clone, Copy, Debug)]
    pub struct SslErrorStack;

    impl std::fmt::Display for SslErrorStack {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for SslErrorStack {
        fn description(&self) -> &str {
            "openssl feature not enabled"
        }
    }
}

#[allow(unreachable_pub)]
#[cfg(not(feature = "ring"))]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
pub mod not_ring {
    use std;

    #[derive(Clone, Copy, Debug)]
    pub struct KeyRejected;

    #[derive(Clone, Copy, Debug)]
    pub struct Unspecified;

    impl std::fmt::Display for KeyRejected {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for KeyRejected {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }

    impl std::fmt::Display for Unspecified {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }

    impl std::error::Error for Unspecified {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }
}
