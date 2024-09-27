// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Error types for the crate

#![deny(missing_docs)]

use std::{fmt, io, sync::Arc};

use crate::proto::error::ForwardNSData;
use enum_as_inner::EnumAsInner;
use hickory_proto::error::ProtoErrorKind;
use hickory_resolver::Name;
use thiserror::Error;

use crate::proto::rr::{rdata::SOA, Record};
#[cfg(feature = "backtrace")]
use crate::proto::{trace, ExtBacktrace};
use crate::{proto::error::ProtoError, resolver::error::ResolveError};

/// The error kind for errors that get returned in the crate
#[derive(Debug, EnumAsInner, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An error with an arbitrary message, referenced as &'static str
    #[error("{0}")]
    Message(&'static str),

    /// An error with an arbitrary message, stored as String
    #[error("{0}")]
    Msg(String),

    /// Upstream DNS authority returned a Referral to another nameserver in the form of an SOA record
    #[error("forward response: {0}")]
    Forward(Name),

    /// Upstream DNS authority returned a referral to another set of nameservers in the form of
    /// additional NS records.
    #[error("forward NS Response")]
    ForwardNS(Arc<[ForwardNSData]>),

    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Resolve(ResolveError),

    /// A request timed out
    #[error("request timed out")]
    Timeout,
}

/// The error type for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub struct Error {
    /// Kind of error that ocurred
    pub kind: Box<ErrorKind>,
    /// Backtrace to the source of the error
    #[cfg(feature = "backtrace")]
    pub backtrack: Option<ExtBacktrace>,
}

impl Error {
    /// Get the kind of the error
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Returns true if the domain does not exist
    pub fn is_nx_domain(&self) -> bool {
        match &*self.kind {
            ErrorKind::Proto(proto) => proto.is_nx_domain(),
            ErrorKind::Resolve(err) => err.is_nx_domain(),
            _ => false,
        }
    }

    /// Returns true if no records were returned
    pub fn is_no_records_found(&self) -> bool {
        match &*self.kind {
            ErrorKind::Proto(proto) => proto.is_no_records_found(),
            ErrorKind::Resolve(err) => err.is_no_records_found(),
            _ => false,
        }
    }

    /// Returns the SOA record, if the error contains one
    pub fn into_soa(self) -> Option<Box<Record<SOA>>> {
        match *self.kind {
            ErrorKind::Proto(proto) => proto.into_soa(),
            ErrorKind::Resolve(err) => err.into_soa(),
            _ => None,
        }
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

impl<E> From<E> for Error
where
    E: Into<ErrorKind>,
{
    fn from(error: E) -> Self {
        let kind: ErrorKind = error.into();

        Self {
            kind: Box::new(kind),
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

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match *e.kind() {
            ErrorKind::Timeout => Self::new(io::ErrorKind::TimedOut, e),
            _ => Self::new(io::ErrorKind::Other, e),
        }
    }
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

impl From<ResolveError> for Error {
    fn from(e: ResolveError) -> Self {
        if let Some(ProtoErrorKind::NoRecordsFound { soa, ns, .. }) =
            e.proto().map(ProtoError::kind)
        {
            if let Some(ns) = ns {
                ErrorKind::ForwardNS(ns.clone()).into()
            } else if let Some(soa) = soa {
                ErrorKind::Forward(soa.name().clone()).into()
            } else {
                ErrorKind::Resolve(e).into()
            }
        } else {
            ErrorKind::Resolve(e).into()
        }
    }
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        use self::ErrorKind::*;
        match *self {
            Message(msg) => Message(msg),
            Msg(ref msg) => Msg(msg.clone()),
            Forward(ref ns) => Forward(ns.clone()),
            ForwardNS(ref ns) => ForwardNS(ns.clone()),
            Io(ref io) => Io(std::io::Error::from(io.kind())),
            Proto(ref proto) => Proto(proto.clone()),
            Resolve(ref resolve) => Resolve(resolve.clone()),
            Timeout => Self::Timeout,
        }
    }
}

/// A trait marking a type which implements `From<Error>` and
/// std::error::Error types as well as Clone + Send
pub trait FromError: From<Error> + std::error::Error + Clone {}

impl<E> FromError for E where E: From<Error> + std::error::Error + Clone {}
