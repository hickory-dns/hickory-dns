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
use std::str::Utf8Error;

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
        Proto(::trust_dns_proto::error::ProtoError, ::trust_dns_proto::error::ProtoErrorKind);
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`. These will be
    // boxed as the error cause and wrapped in a new error with,
    // in this case, the `ErrorKind::Temp` variant.
    //
    // This section can be empty.
    foreign_links {
      Utf8(Utf8Error);
      ParseInt(num::ParseIntError);
    }

    // Define additional `ErrorKind` variants. The syntax here is
    // the same as `quick_error!`, but the `from()` and `cause()`
    // syntax is not supported.
    errors {
      IllegalCharacter(ch: char) {
        description("illegal character input")
        display("illegal character input: {}", ch)
      }

      UnrecognizedChar(ch: char) {
        description("unrecognized character input")
        display("unrecognized character input: {}", ch)
      }

      UnrecognizedOctet(octet: u32) {
        description("unrecognized octet")
        display("unrecognized octet: {:x}", octet)
      }

      UnclosedQuotedString {
        description("unclosed quoted string")
        display("unclosed quoted string")
      }

      UnclosedList {
        description("unclosed list, missing ')'")
        display("unclosed list, missing ')'")
      }

      UnrecognizedDollar(string: String) {
        description("unrecognized dollar content")
        display("unrecognized dollar content: {}", string)
      }

      EOF {
        description("unexpected end of input")
        display("unexpected end of input")
      }

      IllegalState(string: &'static str) {
        description("illegal state")
        display("illegal state: {}", string)
      }
    }
}
