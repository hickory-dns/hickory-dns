// Copyright 2015-2016 Benjamin Fry
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::error::Error;
use std::fmt;

use rusqlite;

pub enum PersistenceError {
  DecodeError(super::ErrorLoc, super::DecodeError),
  EncodeError(super::ErrorLoc, super::EncodeError),
  SqliteError(super::ErrorLoc, rusqlite::Error),
  WrongInsertCount{ loc: super::ErrorLoc, got: i32, expect: i32 },
  RecoveryError(super::ErrorLoc, String),
}

impl fmt::Debug for PersistenceError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Display::fmt(&self, f)
  }
}

impl fmt::Display for PersistenceError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      PersistenceError::DecodeError(ref err_loc, ref err) => write!(f, "{}:{}", err_loc, err),
      PersistenceError::EncodeError(ref err_loc, ref err) => write!(f, "{}:{}", err_loc, err),
      PersistenceError::SqliteError(ref err_loc, ref err) => write!(f, "{}: {}", err_loc, err),
      PersistenceError::WrongInsertCount{ref loc, got, expect } => write!(f, "{}: got {}, expected: {}", loc, got, expect),
      PersistenceError::RecoveryError(ref err_loc, ref msg) => write!(f, "{}: error recovering: {}", err_loc, msg),
    }
  }
}

impl Error for PersistenceError {
  fn description(&self) -> &str {
    match *self {
      PersistenceError::DecodeError(_, ref err) => err.description(),
      PersistenceError::EncodeError(_, ref err) => err.description(),
      PersistenceError::SqliteError(_, ref err) => err.description(),
      PersistenceError::WrongInsertCount{ .. } => "an unexpected number of records were inserted",
      PersistenceError::RecoveryError( .. ) => "error recovering from journal",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      PersistenceError::DecodeError(_, ref err) => Some(err),
      PersistenceError::EncodeError(_, ref err) => Some(err),
      PersistenceError::SqliteError(_, ref err) => Some(err),
      _ => None,
    }
  }
}
