// Copyright 2015-2016 Benjamin Fry
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Base Error type and macro for creating
use std::fmt;

pub struct ErrorLoc{ pub file: &'static str, pub line: u32, pub col: u32 }

macro_rules! error_loc {
  () => { ::error::ErrorLoc { file: file!(), line: line!(), col: column!() } };
}

macro_rules! try_rethrow {
  ( $error_type:path, $error:expr ) => {
    match $error {
      Ok(r) => r,
      Err(e) => return Err($error_type( error_loc!(), e )),
    }
  };
}

impl fmt::Debug for ErrorLoc {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}:{}:{}", self.file, self.line, self.col)
  }
}

impl fmt::Display for ErrorLoc {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}:{}:{}", self.file, self.line, self.col)
  }
}
