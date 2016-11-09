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

use std::io::Error as IoError;
use std::sync::Arc;

use backtrace::Backtrace;
use futures::Canceled;
use openssl::error::ErrorStack as SslErrorStack;

use ::op::ResponseCode;
use ::rr::{Name, Record};
use ::rr::dnssec::{DnsSecError, DnsSecErrorKind};

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
      super::decode_error::Error, super::decode_error::ErrorKind, Decode;
      super::encode_error::Error, super::encode_error::ErrorKind, Encode;
      DnsSecError, DnsSecErrorKind, DnsSec;
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`. These will be
    // boxed as the error cause and wrapped in a new error with,
    // in this case, the `ErrorKind::Temp` variant.
    //
    // This section can be empty.
    foreign_links {
      IoError, Io, "io error";
      SslErrorStack, SSL, "ssl error";
    }

    // Define additional `ErrorKind` variants. The syntax here is
    // the same as `quick_error!`, but the `from()` and `cause()`
    // syntax is not supported.
    errors {
      Canceled(c: Canceled) {
        description("future was canceled")
        display("future was canceled: {:?}", c)
      }

      Message(msg: &'static str) {
        description(msg)
        display("{}", msg)
      }

      NotAllBytesSent(sent: usize, expect: usize) {
        description("not all bytes were sent")
        display("not all bytes were sent: {}, expected: {}", sent, expect)
      }

      NotAllBytesReceived(received: usize, expect: usize) {
        description("not all bytes were recieved")
        display("not all bytes were recieved: {}, expected: {}", received, expect)
      }

      IncorrectMessageId(got: u16, expect: u16) {
        description("incorrectMessageId received")
        display("incorrectMessageId got: {}, expected: {}", got, expect)
      }

      ErrorResponse(response_code: ResponseCode) {
        description("response was an error")
        display("response was an error: {}", response_code.to_str())
      }

      // TODO: add record to which this applies
      NoRRSIG {
        description("no rrsig was recieved")
        display("no rrsig was recieved")
      }

      // TODO: add record to which this applies
      NoDNSKEY {
        description("no dnskey proof available")
        display("no dnskey proof available")
      }

      // TODO: add record to which this applies
      NoDS {
        description("no ds proof available")
        display("no ds proof available")
      }
      //
      NoSOARecord(name: Name) {
        description("no soa record found")
        display("no soa record found for zone: {}", name)
      }

      SecNxDomain(proof: Vec<Record>) {
        description("verified secure non-existence")
        display("verified secure non-existence: {:?}", proof)
      }

      Timeout {
        description("request timeout")
        display("request timed out")
      }
    }
}

impl From<Canceled> for Error {
  fn from(c: Canceled) -> Self {
    Error(ErrorKind::Canceled(c), (None, Arc::new(Backtrace::new())))
  }
}

impl Clone for Error {
  fn clone(&self) -> Self {
    ErrorKind::Msg(format!("ClientError: {}", self)).into()
  }
}
