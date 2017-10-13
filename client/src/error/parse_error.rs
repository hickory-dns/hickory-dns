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
use std::num;
use std::io;
use std::net::AddrParseError;

use super::decode_error;
use super::lexer_error;
use serialize::txt::Token;

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
      decode_error::Error, decode_error::ErrorKind, Decode;
      lexer_error::Error, lexer_error::ErrorKind, Lexer;
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`. These will be
    // boxed as the error cause and wrapped in a new error with,
    // in this case, the `ErrorKind::Temp` variant.
    //
    // This section can be empty.
    foreign_links {
      io::Error, Io, "io error";
      num::ParseIntError, ParseInt, "parse int error";
      AddrParseError, AddrParse, "address parse error";
    }

    // Define additional `ErrorKind` variants. The syntax here is
    // the same as `quick_error!`, but the `from()` and `cause()`
    // syntax is not supported.
    errors {
      Message(msg: &'static str) {
        description(msg)
        display("{}", msg)
      }

      UnexpectedToken(token: Token) {
        description("unrecognized token in stream")
        display("unrecognized token in stream: {:?}", token)
      }

      MissingToken(string: String) {
        description("token is missing")
        display("token is missing: {}", string)
      }

      CharToIntError(ch: char) {
        description("invalid numerical character")
        display("invalid numerical character: {}", ch)
      }

      ParseTimeError(string: String) {
        description("invalid time string")
        display("invalid time string: {}", string)
      }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, format!("DNS ParseError: {}", e))
    }
}