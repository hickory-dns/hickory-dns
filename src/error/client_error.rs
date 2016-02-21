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
use std::io;
use std::fmt;

use ::op::ResponseCode;
use ::rr::Name;

#[derive(Debug)]
pub enum ClientError {
  DecodeError(super::DecodeError),
  EncodeError(super::EncodeError),
  IoError(io::Error),
  NotAllBytesSent{ sent: usize, expect: usize},
  NotAllBytesReceived{ received: usize, expect: usize},
  IncorrectMessageId{ got: u16, expect: u16},
  TimedOut,
  NoAddress,
  NoNameServer,
  TimerError,
  NoDataReceived,
  ErrorResponse(ResponseCode),
  NoRRSIG,
  NoSOARecord(Name),
}

impl fmt::Display for ClientError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      ClientError::DecodeError(ref err) => err.fmt(f),
      ClientError::EncodeError(ref err) => err.fmt(f),
      ClientError::IoError(ref err) => err.fmt(f),
      ClientError::NotAllBytesSent{ sent, expect } => write!(f, "Not all bytes were sent: {}, expected: {}", sent, expect),
      ClientError::NotAllBytesReceived{ received, expect } => write!(f, "Not all bytes were sent: {}, expected: {}", received, expect),
      ClientError::IncorrectMessageId { got, expect } => write!(f, "IncorrectMessageId got: {}, expected: {}", got, expect),
      ClientError::TimedOut => write!(f, "TimedOut awaiting response from server(s)"),
      ClientError::NoAddress => write!(f, "No address received in response"),
      ClientError::NoNameServer => write!(f, "No name server address available"),
      ClientError::TimerError => write!(f, "Error setting timer"),
      ClientError::NoDataReceived => write!(f, "No data was received from the remote"),
      ClientError::ErrorResponse(response_code) => write!(f, "Response was an error: {}", response_code.to_str()),
      ClientError::NoRRSIG => write!(f, "No RRSIG was recieved"),
      ClientError::NoSOARecord(ref name) => write!(f, "No SOA record found for {}", name)
    }
  }
}

impl Error for ClientError {
  fn description(&self) -> &str {
    match *self {
      ClientError::DecodeError(ref err) => err.description(),
      ClientError::EncodeError(ref err) => err.description(),
      ClientError::IoError(ref err) => err.description(),
      ClientError::NotAllBytesSent{ .. } => "Not all bytes were sent",
      ClientError::NotAllBytesReceived{ .. } => "Not all bytes were received",
      ClientError::IncorrectMessageId { .. } => "IncorrectMessageId received",
      ClientError::TimedOut => "TimedOut",
      ClientError::NoAddress => "NoAddress received",
      ClientError::NoNameServer => "No name server address available",
      ClientError::TimerError => "Error setting timer",
      ClientError::NoDataReceived => "No data was received from the remote",
      ClientError::ErrorResponse(..) => "Response was an error",
      ClientError::NoRRSIG => "No RRSIG was recieved",
      ClientError::NoSOARecord(..) => "No SOA record found",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      ClientError::DecodeError(ref err) => Some(err),
      ClientError::EncodeError(ref err) => Some(err),
      ClientError::IoError(ref err) => Some(err),
      _ => None,
    }
  }
}

impl From<super::DecodeError> for ClientError {
  fn from(err: super::DecodeError) -> Self {
    ClientError::DecodeError(err)
  }
}

impl From<super::EncodeError> for ClientError {
  fn from(err: super::EncodeError) -> Self {
    ClientError::EncodeError(err)
  }
}

impl From<io::Error> for ClientError {
  fn from(err: io::Error) -> Self {
    ClientError::IoError(err)
  }
}
