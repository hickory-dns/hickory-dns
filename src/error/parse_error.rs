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
use std::num;
use std::io;
use std::net::AddrParseError;

use super::DecodeError;
use super::LexerError;
use ::serialize::txt::Token;

#[derive(Debug)]
pub enum ParseError {
  LexerError(LexerError),
  DecodeError(DecodeError),
  UnexpectedToken(Token),
  OriginIsUndefined,
  RecordTypeNotSpecified,
  RecordNameNotSpecified,
  RecordClassNotSpecified,
  RecordTTLNotSpecified,
  RecordDataNotSpecified,
  SoaAlreadySpecified,
  MissingToken(String),
  IoError(io::Error),
  ParseIntError(num::ParseIntError),
  AddrParseError(AddrParseError),
}

impl fmt::Display for ParseError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      ParseError::LexerError(ref err) => err.fmt(f),
      ParseError::DecodeError(ref err) => err.fmt(f),
      ParseError::UnexpectedToken(ref t) => write!(f, "Unrecognized Token in stream: {:?}", t),
      ParseError::OriginIsUndefined => write!(f, "$ORIGIN was not specified"),
      ParseError::RecordTypeNotSpecified => write!(f, "Record type not specified"),
      ParseError::RecordNameNotSpecified => write!(f, "Record name not specified"),
      ParseError::RecordClassNotSpecified => write!(f, "Record class not specified"),
      ParseError::RecordTTLNotSpecified => write!(f, "Record ttl not specified"),
      ParseError::RecordDataNotSpecified => write!(f, "Record data not specified"),
      ParseError::SoaAlreadySpecified => write!(f, "SOA is already specified"),
      ParseError::MissingToken(ref s) => write!(f, "Token is missing: {}", s),
      ParseError::IoError(ref err) => err.fmt(f),
      ParseError::ParseIntError(ref err) => err.fmt(f),
      ParseError::AddrParseError(ref s) => write!(f, "Could not parse address: {:?}", s),
    }
  }
}

impl Error for ParseError {
  fn description(&self) -> &str {
    match *self {
      ParseError::LexerError(ref err) => err.description(),
      ParseError::DecodeError(ref err) => err.description(),
      ParseError::UnexpectedToken(..) => "Unrecognized Token",
      ParseError::OriginIsUndefined => "$ORIGIN was not specified",
      ParseError::RecordTypeNotSpecified => "Record type not specified",
      ParseError::RecordNameNotSpecified => "Record name not specified",
      ParseError::RecordClassNotSpecified => "Record class not specified",
      ParseError::RecordTTLNotSpecified => "Record ttl not specified",
      ParseError::RecordDataNotSpecified => "Record data not specified",
      ParseError::SoaAlreadySpecified => "SOA is already specified",
      ParseError::MissingToken(..) => "Token is missing",
      ParseError::IoError(ref err) => err.description(),
      ParseError::ParseIntError(ref err) => err.description(),
      ParseError::AddrParseError(..) => "Could not parse address",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      ParseError::LexerError(ref err) => Some(err),
      ParseError::DecodeError(ref err) => Some(err),
      ParseError::IoError(ref err) => Some(err),
      ParseError::ParseIntError(ref err) => Some(err),
      _ => None,
    }
  }
}

impl From<LexerError> for ParseError {
  fn from(err: LexerError) -> ParseError {
    ParseError::LexerError(err)
  }
}

impl From<DecodeError> for ParseError {
  fn from(err: DecodeError) -> ParseError {
    ParseError::DecodeError(err)
  }
}

impl From<io::Error> for ParseError {
  fn from(err: io::Error) -> ParseError {
    ParseError::IoError(err)
  }
}

impl From<num::ParseIntError> for ParseError {
  fn from(err: num::ParseIntError) -> ParseError {
    ParseError::ParseIntError(err)
  }
}

impl From<AddrParseError> for ParseError {
  fn from(err: AddrParseError) -> ParseError {
    ParseError::AddrParseError(err)
  }
}
