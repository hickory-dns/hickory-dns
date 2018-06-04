// Copyright 2015-2016 Benjamin Fry
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use rusqlite;

use trust_dns::error::*;
use trust_dns_proto::error::*;

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
    DnsSec(DnsSecError, DnsSecErrorKind);
    ProtoError(ProtoError, ProtoErrorKind);
  }

  // Automatic conversions between this error chain and other
  // error types not defined by the `error_chain!`. These will be
  // boxed as the error cause and wrapped in a new error with,
  // in this case, the `ErrorKind::Temp` variant.
  //
  // This section can be empty.
  foreign_links {
    Sqlite(rusqlite::Error);
  }

  // Define additional `ErrorKind` variants. The syntax here is
  // the same as `quick_error!`, but the `from()` and `cause()`
  // syntax is not supported.
  errors {
    WrongInsertCount(got: i32, expect: i32) {
      description("wrong insert count")
      display("wrong insert count: {} expect: {}", got, expect)
    }

    RecoveryError(msg: &'static str) {
      description("error recovering from journal")
      display("error recovering from journal: {}", msg)
    }
  }
}
