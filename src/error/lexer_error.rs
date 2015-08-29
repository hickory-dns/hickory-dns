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
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum LexerError {
  ParseUtf8Error(FromUtf8Error),
  EscapedCharOutsideCharData,
  IllegalCharacter(char),
  UnrecognizedChar(char),
  BadEscapedData(String),
  UnrecognizedOctet(u32),
  ParseIntError(num::ParseIntError),
  UnclosedQuotedString,
  UnclosedList,
  UnrecognizedDollar(String),
  EOF,
}

impl fmt::Display for LexerError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      LexerError::ParseUtf8Error(ref err) => err.fmt(f),
      LexerError::EscapedCharOutsideCharData => write!(f, "Escaped character outside character data"),
      LexerError::IllegalCharacter(ch) => write!(f, "Illegal input character: {}", ch),
      LexerError::UnrecognizedChar(ch) => write!(f, "Did not recognize the input character: {}", ch),
      LexerError::BadEscapedData(ref s) => write!(f, "Illegal input character: {}", s),
      LexerError::UnrecognizedOctet(o) => write!(f, "Unrecognized octet: {}", o),
      LexerError::ParseIntError(ref err) => err.fmt(f),
      LexerError::UnclosedQuotedString => write!(f, "Unclosed quoted string"),
      LexerError::UnclosedList => write!(f, "Unclosed list, missing ')'"),
      LexerError::UnrecognizedDollar(ref s) => write!(f, "Unrecognized dollar content: {}", s),
      LexerError::EOF => write!(f, "End of input reached before next read could complete"),
    }
  }
}

impl Error for LexerError {
  fn description(&self) -> &str {
    match *self {
      LexerError::ParseUtf8Error(ref err) => err.description(),
      LexerError::EscapedCharOutsideCharData => "Escaped character outside character data",
      LexerError::IllegalCharacter(..) => "Illegal character input",
      LexerError::UnrecognizedChar(..) => "Unrecognized character input",
      LexerError::BadEscapedData(..) => "Escaped data not recognized",
      LexerError::UnrecognizedOctet(..) => "Unrecognized octet",
      LexerError::ParseIntError(ref err) => err.description(),
      LexerError::UnclosedQuotedString => "Unclosed quoted string",
      LexerError::UnclosedList => "Unclosed list",
      LexerError::UnrecognizedDollar(..) => "Unrecognized dollar content",
      LexerError::EOF => "End of input",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      LexerError::ParseUtf8Error(ref err) => Some(err),
      LexerError::ParseIntError(ref err) => Some(err),
      _ => None,
    }
  }
}

impl From<FromUtf8Error> for LexerError {
    fn from(err: FromUtf8Error) -> LexerError {
        LexerError::ParseUtf8Error(err)
    }
}

impl From<num::ParseIntError> for LexerError {
    fn from(err: num::ParseIntError) -> LexerError {
        LexerError::ParseIntError(err)
    }
}
