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
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum DecodeError {
  ParseUtf8Error(FromUtf8Error),
  UnknownDnsClassValue(u16),
  UnknownDnsClassStr(String),
  UnknownRecordTypeValue(u16),
  UnknownRecordTypeStr(String),
  UnknownAlgorithmTypeValue(u8),
  NoRecordDataType,
  NoRecordDataLength,
  EOF,
  Sig0NotLast,
  EdnsNameNotRoot,
  DnsKeyProtocolNot3(u8),
  UnrecognizedNsec3Flags(u8),
  UnrecognizedLabelCode(u8),
  IncorrectRDataLengthRead(usize, usize)
}

impl fmt::Display for DecodeError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      DecodeError::ParseUtf8Error(ref err) => err.fmt(f),
      DecodeError::UnknownDnsClassValue(ref val) => write!(f, "DnsClass value unknown: {}", val),
      DecodeError::UnknownDnsClassStr(ref val) => write!(f, "DnsClass string unknown: {}", val),
      DecodeError::UnknownRecordTypeValue(ref val) => write!(f, "RecordType value unknown: {}", val),
      DecodeError::UnknownRecordTypeStr(ref val) => write!(f, "RecordType string unknown: {}", val),
      DecodeError::UnknownAlgorithmTypeValue(ref val) => write!(f, "AlgorithmType value unknown: {}", val),
      DecodeError::NoRecordDataType => write!(f, "There was no record data type specified"),
      DecodeError::NoRecordDataLength => write!(f, "There was no record data length specified"),
      DecodeError::EOF => write!(f, "End of input reached before next read could complete"),
      DecodeError::Sig0NotLast => write!(f, "SIG0 must be final resource record"),
      DecodeError::EdnsNameNotRoot => write!(f, "EDNS resource record label must be the root label (.)"),
      DecodeError::DnsKeyProtocolNot3(ref val) => write!(f, "DnsKey value unknown, must be 3: {}", val),
      DecodeError::UnrecognizedNsec3Flags(ref val) => write!(f, "Nsec3 flags should be 0b0000000*: {:b}", val),
      DecodeError::UnrecognizedLabelCode(ref val) => write!(f, "Unrecognized Label Code: {:b}", val),
      DecodeError::IncorrectRDataLengthRead(ref read, ref rdata_length) => write!(f, "IncorrectRDataLengthRead read: {}, expected: {}", read, rdata_length),
    }
  }
}

impl Error for DecodeError {
  fn description(&self) -> &str {
    match *self {
      DecodeError::ParseUtf8Error(ref err) => err.description(),
      DecodeError::UnknownDnsClassValue(..) => "DnsClass value unknown",
      DecodeError::UnknownDnsClassStr(..) => "DnsClass string unknown",
      DecodeError::UnknownRecordTypeValue(..) => "RecordType value unknown",
      DecodeError::UnknownRecordTypeStr(..) => "RecordType string unknown",
      DecodeError::UnknownAlgorithmTypeValue(..) => "AlgorithmType value unknown",
      DecodeError::NoRecordDataType => "RecordType unspecified",
      DecodeError::NoRecordDataLength => "RecordData length unspecified",
      DecodeError::EOF => "End of input",
      DecodeError::Sig0NotLast => "SIG0 must be final resource record",
      DecodeError::EdnsNameNotRoot => "EDNS resource record label must be the root label (.)",
      DecodeError::DnsKeyProtocolNot3(..) => "DnsKey value unknown, must be 3",
      DecodeError::UnrecognizedNsec3Flags(..) => "Nsec3 flags should be 0b0000000*",
      DecodeError::UnrecognizedLabelCode(..) => "Unrecognized label code",
      DecodeError::IncorrectRDataLengthRead(..) => "IncorrectRDataLengthRead",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      DecodeError::ParseUtf8Error(ref err) => Some(err),
      _ => None,
    }
  }
}

impl From<FromUtf8Error> for DecodeError {
    fn from(err: FromUtf8Error) -> DecodeError {
        DecodeError::ParseUtf8Error(err)
    }
}
