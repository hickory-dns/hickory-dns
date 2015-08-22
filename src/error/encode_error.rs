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

#[derive(Debug)]
pub enum EncodeError {
  CharacterDataTooLong(usize),
  LabelBytesTooLong(usize),
  DomainNameTooLong(usize),
}

impl fmt::Display for EncodeError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      EncodeError::CharacterDataTooLong(length) => write!(f, "Char data exceeds 255: {}", length),
      EncodeError::LabelBytesTooLong(length) => write!(f, "Label bytes exceed 63: {}", length),
      EncodeError::DomainNameTooLong(length) => write!(f, "Name data exceed 255: {}", length),
    }
  }
}

impl Error for EncodeError {
  fn description(&self) -> &str {
    match *self {
      EncodeError::CharacterDataTooLong(..) => "Char data length exceeds 255",
      EncodeError::LabelBytesTooLong(..) => "Label bytes exceed 63",
      EncodeError::DomainNameTooLong(..) => "Name data exceed 255",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      _ => None,
    }
  }
}
