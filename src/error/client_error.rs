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
use ::rr::{Name, Record};

pub enum ClientError {
  DecodeError(super::ErrorLoc, super::DecodeError),
  EncodeError(super::ErrorLoc, super::EncodeError),
  IoError(super::ErrorLoc, io::Error),
  NotAllBytesSent{ loc: super::ErrorLoc, sent: usize, expect: usize},
  NotAllBytesReceived{ loc: super::ErrorLoc, received: usize, expect: usize},
  IncorrectMessageId{ loc: super::ErrorLoc, got: u16, expect: u16},
  TimedOut(super::ErrorLoc),
  NoAddress(super::ErrorLoc),
  NoNameServer(super::ErrorLoc),
  TimerError(super::ErrorLoc),
  NoDataReceived(super::ErrorLoc),
  ErrorResponse(super::ErrorLoc, ResponseCode),
  NoRRSIG(super::ErrorLoc),
  NoDNSKEY(super::ErrorLoc),
  NoDS(super::ErrorLoc),
  NoSOARecord(super::ErrorLoc, Name),
  SecNxDomain{ loc: super::ErrorLoc, proof: Vec<Record>},
  InvalidNsec(super::ErrorLoc),
  InvalidNsec3(super::ErrorLoc),
  NoNsec(super::ErrorLoc),
}

impl fmt::Debug for ClientError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::Display::fmt(&self, f)
  }
}

impl fmt::Display for ClientError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      ClientError::DecodeError(ref err_loc, ref err) => write!(f, "{}:{}", err_loc, err),
      ClientError::EncodeError(ref err_loc, ref err) => write!(f, "{}:{}", err_loc, err),
      ClientError::IoError(ref err_loc, ref err) => write!(f, "{}:{}", err_loc, err),
      ClientError::NotAllBytesSent{ ref loc, sent, expect } => write!(f, "{}: Not all bytes were sent: {}, expected: {}", loc, sent, expect),
      ClientError::NotAllBytesReceived{ ref loc, received, expect } => write!(f, "{}: Not all bytes were sent: {}, expected: {}", loc, received, expect),
      ClientError::IncorrectMessageId { ref loc, got, expect } => write!(f, "{}: IncorrectMessageId got: {}, expected: {}", loc, got, expect),
      ClientError::TimedOut(ref loc) => write!(f, "{}: TimedOut awaiting response from server(s)", loc),
      ClientError::NoAddress(ref loc) => write!(f, "{}: No address received in response", loc),
      ClientError::NoNameServer(ref loc) => write!(f, "{}: No name server address available", loc),
      ClientError::TimerError(ref loc) => write!(f, "{}: Error setting timer", loc),
      ClientError::NoDataReceived(ref loc) => write!(f, "{}: No data was received from the remote", loc),
      ClientError::ErrorResponse(ref loc, response_code) => write!(f, "{}: Response was an error: {}", loc, response_code.to_str()),
      ClientError::NoRRSIG(ref loc) => write!(f, "{}: No RRSIG was recieved", loc),
      ClientError::NoDS(ref loc) => write!(f, "{}: No DS was recieved", loc),
      ClientError::NoDNSKEY(ref loc) => write!(f, "{}: No DNSKEY proof available", loc),
      ClientError::NoSOARecord(ref loc, ref name) => write!(f, "{}: No SOA record found for {}", loc, name),
      ClientError::SecNxDomain{ref loc, ..} => write!(f, "{}: Verified secure non-existence", loc),
      ClientError::InvalidNsec(ref loc) => write!(f, "{}: Can not validate NSEC records", loc),
      ClientError::InvalidNsec3(ref loc) => write!(f, "{}: Can not validate NSEC3 records", loc),
      ClientError::NoNsec(ref loc) => write!(f, "{}: No NSEC(3) records to validate NXDOMAIN", loc),
    }
  }
}

impl Error for ClientError {
  fn description(&self) -> &str {
    match *self {
      ClientError::DecodeError(_, ref err) => err.description(),
      ClientError::EncodeError(_, ref err) => err.description(),
      ClientError::IoError(_, ref err) => err.description(),
      ClientError::NotAllBytesSent{ .. } => "Not all bytes were sent",
      ClientError::NotAllBytesReceived{ .. } => "Not all bytes were received",
      ClientError::IncorrectMessageId { .. } => "IncorrectMessageId received",
      ClientError::TimedOut(..) => "TimedOut",
      ClientError::NoAddress(..) => "NoAddress received",
      ClientError::NoNameServer(..) => "No name server address available",
      ClientError::TimerError(..) => "Error setting timer",
      ClientError::NoDataReceived(..) => "No data was received from the remote",
      ClientError::ErrorResponse(..) => "Response was an error",
      ClientError::NoRRSIG(..) => "No RRSIG was recieved",
      ClientError::NoDS(..) => "No DS was recieved",
      ClientError::NoDNSKEY(..) => "No DNSKEY proof available",
      ClientError::NoSOARecord(..) => "No SOA record found",
      ClientError::SecNxDomain{ .. } => "Verified secure non-existence",
      ClientError::InvalidNsec(..) => "Can not validate NSEC records",
      ClientError::InvalidNsec3(..) => "Can not validate NSEC3 records",
      ClientError::NoNsec(..) => "No NSEC(3) records to validate NXDOMAIN",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      ClientError::DecodeError(_, ref err) => Some(err),
      ClientError::EncodeError(_, ref err) => Some(err),
      ClientError::IoError(_, ref err) => Some(err),
      _ => None,
    }
  }
}

// impl From<super::DecodeError> for ClientError {
//   fn from(err: super::DecodeError) -> Self {
//     ClientError::DecodeError(error_loc!(), err)
//   }
// }

// impl From<super::EncodeError> for ClientError {
//   fn from(err: super::EncodeError) -> Self {
//     ClientError::EncodeError(err)
//   }
// }

// impl From<io::Error> for ClientError {
//   fn from(err: io::Error) -> Self {
//     ClientError::IoError(err)
//   }
// }
