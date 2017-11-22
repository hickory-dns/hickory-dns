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

use std::io;

use futures::sync::mpsc::SendError;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(not(feature = "openssl"))]
use error::dnssec_error::not_openssl::SslErrorStack;

use error::{DnsSecError, DnsSecErrorKind};

error_chain! {
    // The type defined for this error. These are the conventional
    // and recommended names, but they can be arbitrarily chosen.
    types {
        Error, ErrorKind, ChainErr, Result;
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
        DnsSecError, DnsSecErrorKind, DnsSec;
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`. These will be
    // boxed as the error cause and wrapped in a new error with,
    // in this case, the `ErrorKind::Temp` variant.
    //
    // This section can be empty.
    foreign_links {
      io::Error, Io, "io error";
      SslErrorStack, SSL, "ssl error";
    }

    // Define additional `ErrorKind` variants. The syntax here is
    // the same as `quick_error!`, but the `from()` and `cause()`
    // syntax is not supported.
    errors {
      NoError {
        description("no error specified")
        display("no error specified")
      }

      Message(msg: &'static str) {
        description(msg)
        display("{}", msg)
      }


      Timeout {
        description("request timeout")
        display("request timed out")
      }
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        ErrorKind::NoError.into()
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Self {
        ErrorKind::Msg(format!("error sending to mpsc: {}", e)).into()
    }
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match *self.kind() {
            ErrorKind::Timeout => ErrorKind::Timeout.into(),
            _ => ErrorKind::Msg(format!("Cloned error: {}", self)).into(),
        }
    }
}

impl<'a> From<&'a io::Error> for Error {
    fn from(e: &'a io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => ErrorKind::Timeout.into(),
            _ => format!("io::Error: {}", e).into(),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match *e.kind() {
            ErrorKind::Timeout => io::ErrorKind::TimedOut.into(),
            _ => io::Error::new(io::ErrorKind::Other, format!("ClientError: {}", e)),
        }
    }
}

#[test]
fn test_conversion() {
    let io_error = io::Error::new(io::ErrorKind::TimedOut, format!("mock timeout"));

    let error = Error::from(&io_error);

    match error.kind() {
        &ErrorKind::Timeout => (),
        _ => panic!("incorrect type: {}", error),
    }
}
