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

use std::error::Error as StdError;
use std::string::FromUtf8Error;

use openssl::ssl::error::SslError;

use ::rr::Name;

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
  links {}

  // Automatic conversions between this error chain and other
  // error types not defined by the `error_chain!`. These will be
  // boxed as the error cause and wrapped in a new error with,
  // in this case, the `ErrorKind::Temp` variant.
  //
  // This section can be empty.
  foreign_links {
    FromUtf8Error, UTF8, "utf8 error";
    SslError, SSL, "ssl error";
  }

  // Define additional `ErrorKind` variants. The syntax here is
  // the same as `quick_error!`, but the `from()` and `cause()`
  // syntax is not supported.
  errors {
    Message(message: &'static str) {
      description(message)
      display("{}", message)
    }

    InvalidToolchainName(t: String) {
      description("invalid toolchain name")
      display("invalid toolchain name: '{}'", t)
    }

    UnknownDnsClassValue(value: u16) {
      description("dns class value unknown")
      display("dns class value unknown: {}", value)
    }

    UnknownDnsClassStr(value: String) {
      description("dns class string unknown")
      display("dns class string unknown: {}", value)
    }

    UnknownRecordTypeValue(value: u16) {
      description("record type value unknown")
      display("record type value unknown: {}", value)
    }

    UnknownRecordTypeStr(value: String) {
      description("record type string unknown")
      display("record type string unknown: {}", value)
    }

    UnknownAlgorithmTypeValue(value: u8) {
      description("algorithm type value unknown")
      display("algorithm type value unknown: {}", value)
    }

    // TODO: add name
    EdnsNameNotRoot(found: Name) {
      description("edns resource record label must be the root label (.)")
      display("edns resource record label must be the root label (.): {}", found)
    }

    DnsKeyProtocolNot3(value: u8) {
      description("dns key value unknown, must be 3")
      display("dns key value unknown, must be 3: {}", value)
    }

    UnrecognizedNsec3Flags(value: u8) {
      description("nsec3 flags should be 0b0000000*")
      display("nsec3 flags should be 0b0000000*: {:b}", value)
    }

    UnrecognizedLabelCode(value: u8) {
      description("unrecognized label code")
      display("unrecognized label code: {:b}", value)
    }

    IncorrectRDataLengthRead(read: usize, len: usize) {
      description("incorrect rdata length read")
      display("incorrect rdata length read: {} expected: {}", read, len)
    }
  }
}
