// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

use std::{fmt, io, sync};

use thiserror::Error;

#[cfg(feature = "backtrace")]
use crate::proto::{ExtBacktrace, trace};
use crate::proto::{
    ProtoError, ProtoErrorKind,
    rr::{Record, rdata::SOA},
    xfer::retry_dns_handle::RetryableError,
};

#[allow(clippy::large_enum_variant)]
/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ResolveErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),
}

impl Clone for ResolveErrorKind {
    fn clone(&self) -> Self {
        use self::ResolveErrorKind::*;
        match self {
            Message(msg) => Message(msg),
            Msg(msg) => Msg(msg.clone()),
            // foreign
            Proto(proto) => Self::from(proto.clone()),
        }
    }
}

/// The error type for errors that get returned in the crate
#[derive(Debug, Clone, Error)]
pub struct ResolveError {
    pub(crate) kind: ResolveErrorKind,
    #[cfg(feature = "backtrace")]
    backtrack: Option<ExtBacktrace>,
}

impl ResolveError {
    /// Get the kind of the error
    pub fn kind(&self) -> &ResolveErrorKind {
        &self.kind
    }

    /// Take the kind of the error
    pub fn into_kind(self) -> ResolveErrorKind {
        self.kind
    }

    /// If this is an underlying proto error, return that
    pub fn proto(&self) -> Option<&ProtoError> {
        match &self.kind {
            ResolveErrorKind::Proto(proto) => Some(proto),
            _ => None,
        }
    }

    /// Returns true if the domain does not exist
    pub fn is_nx_domain(&self) -> bool {
        self.proto()
            .map(|proto| proto.is_nx_domain())
            .unwrap_or(false)
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        self.proto()
            .map(|proto| proto.is_no_records_found())
            .unwrap_or(false)
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match self.kind {
            ResolveErrorKind::Proto(proto) => proto.into_soa(),
            _ => None,
        }
    }
}

impl RetryableError for ResolveError {
    fn should_retry(&self) -> bool {
        match self.kind() {
            ResolveErrorKind::Message(_) | ResolveErrorKind::Msg(_) => false,
            ResolveErrorKind::Proto(proto) => proto.should_retry(),
        }
    }

    fn attempted(&self) -> bool {
        match self.kind() {
            ResolveErrorKind::Proto(e) => e.attempted(),
            _ => true,
        }
    }
}

impl fmt::Display for ResolveError {
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

impl From<ResolveErrorKind> for ResolveError {
    fn from(kind: ResolveErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "backtrace")]
            backtrack: trace!(),
        }
    }
}

impl From<&'static str> for ResolveError {
    fn from(msg: &'static str) -> Self {
        ResolveErrorKind::Message(msg).into()
    }
}

impl TryFrom<ResolveError> for ProtoErrorKind {
    type Error = ResolveError;
    fn try_from(error: ResolveError) -> Result<Self, Self::Error> {
        match error.kind {
            ResolveErrorKind::Proto(p) => Ok(*p.kind),
            _ => Err(error),
        }
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "system-config")]
impl From<ipconfig::error::Error> for ResolveError {
    fn from(e: ipconfig::error::Error) -> ResolveError {
        ResolveErrorKind::Msg(format!("failed to read from registry: {}", e)).into()
    }
}

impl From<String> for ResolveError {
    fn from(msg: String) -> Self {
        ResolveErrorKind::Msg(msg).into()
    }
}

impl From<io::Error> for ResolveError {
    fn from(e: io::Error) -> Self {
        ResolveErrorKind::from(ProtoError::from(e)).into()
    }
}

impl From<ProtoError> for ResolveError {
    fn from(e: ProtoError) -> Self {
        ResolveErrorKind::Proto(e).into()
    }
}

impl From<ResolveError> for io::Error {
    fn from(e: ResolveError) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

impl<T> From<sync::PoisonError<T>> for ResolveError {
    fn from(e: sync::PoisonError<T>) -> Self {
        ResolveErrorKind::Msg(format!("lock was poisoned, this is non-recoverable: {e}")).into()
    }
}
