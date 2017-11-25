// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(missing_docs)]

use std::io;
use trust_dns_proto::op::Query;

error_chain! {
    // The type defined for this error. These are the conventional
    // and recommended names, but they can be arbitrarily chosen.
    types {
        ResolveError, ResolveErrorKind, ResolveChainErr, ResolveResult;
    }

    // Automatic conversions between this error chain and other
    // error chains. In this case, it will e.g. generate an
    // `ErrorKind` variant called `Dist` which in turn contains
    // the `rustup_dist::ErrorKind`, with conversions from
    // `rustup_dist::Error`.
    //
    // This section can be empty.
    links {
        ::trust_dns_proto::error::ProtoError, ::trust_dns_proto::error::ProtoErrorKind, Proto;
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`. These will be
    // boxed as the error cause and wrapped in a new error with,
    // in this case, the `ErrorKind::Temp` variant.
    //
    // This section can be empty.
    foreign_links {
      ::std::io::Error, Io, "io error";
    }

    // Define additional `ErrorKind` variants. The syntax here is
    // the same as `quick_error!`, but the `from()` and `cause()`
    // syntax is not supported.
    errors {
        Message(msg: &'static str) {
            description(msg)
            display("{}", msg)
        }

        NoRecordsFound(query: Query) {
            description("no record found for name")
            display("no record found for {}", query)
        }
    }
}

impl Clone for ResolveErrorKind {
    fn clone(&self) -> Self {
        match self {
            &ResolveErrorKind::Io => ResolveErrorKind::Io,
            &ResolveErrorKind::Message(ref string) => ResolveErrorKind::Message(string),
            &ResolveErrorKind::Msg(ref string) => ResolveErrorKind::Msg(string.clone()),
            &ResolveErrorKind::NoRecordsFound(ref query) => {
                ResolveErrorKind::NoRecordsFound(query.clone())
            }
            &ResolveErrorKind::Proto(ref kind) => ResolveErrorKind::Proto(kind.clone()),
        }
    }
}

impl Clone for ResolveError {
    fn clone(&self) -> Self {
        let cloned_kind: ResolveErrorKind = self.0.clone();

        let inner_error: Option<Box<::std::error::Error + Send + 'static>> =
            (&self.1).0.as_ref().map(|e| {
                Box::new(ResolveError::from(ResolveErrorKind::Msg(format!("{}", e))))
                    as Box<::std::error::Error + Send + 'static>
            });
        ResolveError(cloned_kind, (inner_error, (self.1).1.clone()))
    }
}

// This is an expensive comparison option, only available for testing...
#[cfg(test)]
impl PartialEq for ResolveErrorKind {
    fn eq(&self, other: &ResolveErrorKind) -> bool {
        self.to_string() == other.to_string()
    }
}

impl From<ResolveError> for io::Error {
    fn from(e: ResolveError) -> Self {
        match e.kind() {
            _ => io::Error::new(io::ErrorKind::Other, format!("ResolveError: {}", e)),
        }
    }
}
