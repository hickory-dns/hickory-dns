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
use std::error::Error;
use std::fmt;
use std::io;

use toml::ParserError;
use toml::DecodeError;


pub enum ConfigError {
  IoError(io::Error),
  ParserError(ParserError),
  VecParserError(Vec<ParserError>),
  DecodeError(DecodeError),
}

impl fmt::Debug for ConfigError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Display::fmt(&self, f)
  }
}

impl fmt::Display for ConfigError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      ConfigError::IoError(ref err) => err.fmt(f),
      ConfigError::ParserError(ref err) => err.fmt(f),
      ConfigError::VecParserError(ref errs) => write!(f, "{:?}", errs),
      ConfigError::DecodeError(ref err) => err.fmt(f),
    }
  }
}

impl Error for ConfigError {
  fn description(&self) -> &str {
    match *self {
      ConfigError::IoError(ref err) => err.description(),
      ConfigError::ParserError(ref err) => err.description(),
      ConfigError::VecParserError(..) => "There were errors parsing config",
      ConfigError::DecodeError(ref err) => err.description(),
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      ConfigError::IoError(ref err) => Some(err),
      ConfigError::ParserError(ref err) => Some(err),
      ConfigError::DecodeError(ref err) => Some(err),
      _ => None,
    }
  }
}

impl From<io::Error> for ConfigError {
  fn from(err: io::Error) -> Self {
    ConfigError::IoError(err)
  }
}

impl From<ParserError> for ConfigError {
  fn from(err: ParserError) -> Self {
    ConfigError::ParserError(err)
  }
}


impl From<Vec<ParserError>> for ConfigError {
  fn from(err: Vec<ParserError>) -> Self {
    ConfigError::VecParserError(err)
  }
}

impl From<DecodeError> for ConfigError {
  fn from(err: DecodeError) -> Self {
    ConfigError::DecodeError(err)
  }
}
