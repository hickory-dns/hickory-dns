// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(missing_docs)]

use std::io;
use std::sync::Arc;

use rr::{Name, RecordType};

#[cfg(feature = "openssl")]
use openssl::error::ErrorStack as SslErrorStack;
#[cfg(not(feature = "openssl"))]
use self::not_openssl::SslErrorStack;
#[cfg(feature = "ring")]
use ring::error::Unspecified;
#[cfg(not(feature = "ring"))]
use self::not_ring::Unspecified;

error_chain! {
    // The type defined for this error. These are the conventional
    // and recommended names, but they can be arbitrarily chosen.
    types {
        ProtoError, ProtoErrorKind, ProtoChainErr, ProtoResult;
    }

    // Automatic conversions between this error chain and other
    // error chains. In this case, it will e.g. generate an
    // `ErrorKind` variant called `Dist` which in turn contains
    // the `rustup_dist::ErrorKind`, with conversions from
    // `rustup_dist::Error`.
    //
    // This section can be empty.
    links {
    //   super::decode_error::Error, super::decode_error::ErrorKind, Decode;
    //   super::encode_error::Error, super::encode_error::ErrorKind, Encode;
    //   DnsSecError, ProtoErrorKind, DnsSec;
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`. These will be
    // boxed as the error cause and wrapped in a new error with,
    // in this case, the `ErrorKind::Temp` variant.
    //
    // This section can be empty.
    foreign_links {
      ::std::io::Error, Io, "io error";
      ::std::net::AddrParseError, AddrParseError, "network address parse error";
      ::std::num::ParseIntError, ParseIntError, "error parsing number";
      ::std::str::Utf8Error, Utf8Error, "error parsing utf string";
      ::std::string::FromUtf8Error, FromUtf8Error, "utf8 conversion error";
      SslErrorStack, SSL, "ssl error";
      Unspecified, Ring, "ring error";
      ::url::ParseError, UrlParsingError, "url parsing error";
    }

    // Define additional `ErrorKind` variants. The syntax here is
    // the same as `quick_error!`, but the `from()` and `cause()`
    // syntax is not supported.
    errors {
      Canceled(c: ::futures::sync::oneshot::Canceled) {
        description("future was canceled")
        display("future was canceled: {:?}", c)
      }

      CharacterDataTooLong(len: usize) {
        description("char data length exceeds 255")
        display("char data length exceeds 255: {}", len)
      }

      DnsKeyProtocolNot3(value: u8) {
        description("dns key value unknown, must be 3")
        display("dns key value unknown, must be 3: {}", value)
      }

      DomainNameTooLong(len: usize) {
        description("name label data exceed 255")
        display("name label data exceed 255: {}", len)
      }

      EdnsNameNotRoot(found: ::rr::Name) {
        description("edns resource record label must be the root label (.)")
        display("edns resource record label must be the root label (.): {}", found)
      }

      LabelBytesTooLong(len: usize) {
        description("label bytes exceed 63")
        display("label bytes exceed 63: {}", len)
      }

      Message(msg: &'static str) {
        description(msg)
        display("{}", msg)
      }

      NoError {
        description("no error specified")
        display("no error specified")
      }

      IncorrectRDataLengthRead(read: usize, len: usize) {
        description("incorrect rdata length read")
        display("incorrect rdata length read: {} expected: {}", read, len)
      }

      Timeout {
        description("request timeout")
        display("request timed out")
      }

      UnknownAlgorithmTypeValue(value: u8) {
        description("algorithm type value unknown")
        display("algorithm type value unknown: {}", value)
      }

      UnknownDnsClassStr(value: String) {
        description("dns class string unknown")
        display("dns class string unknown: {}", value)
      }

      UnknownDnsClassValue(value: u16) {
        description("dns class value unknown")
        display("dns class value unknown: {}", value)
      }

      UnrecognizedLabelCode(value: u8) {
        description("unrecognized label code")
        display("unrecognized label code: {:b}", value)
      }

      UnrecognizedNsec3Flags(value: u8) {
        description("nsec3 flags should be 0b0000000*")
        display("nsec3 flags should be 0b0000000*: {:b}", value)
      }

      UnknownRecordTypeStr(value: String) {
        description("record type string unknown")
        display("record type string unknown: {}", value)
      }

      UnknownRecordTypeValue(value: u16) {
        description("record type value unknown")
        display("record type value unknown: {}", value)
      }

      RrsigsNotPresent(name: Name, record_type: RecordType) {
        description("rrsigs are not present for record set")
        display("rrsigs are not present for record set name: {} record_type: {}", name, record_type)
      }
    }
}

#[cfg(not(feature = "openssl"))]
pub mod not_openssl {
    use std;

    #[derive(Debug)]
    pub struct SslErrorStack;

    impl std::fmt::Display for SslErrorStack {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }


    impl std::error::Error for SslErrorStack {
        fn description(&self) -> &str {
            "openssl feature not enabled"
        }
    }
}

#[cfg(not(feature = "ring"))]
pub mod not_ring {
    use std;

    #[derive(Debug)]
    pub struct Unspecified;

    impl std::fmt::Display for Unspecified {
        fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            Ok(())
        }
    }


    impl std::error::Error for Unspecified {
        fn description(&self) -> &str {
            "ring feature not enabled"
        }
    }
}

impl From<ProtoError> for io::Error {
    fn from(e: ProtoError) -> Self {
        let error_kind = match *e.kind() {
            ProtoErrorKind::Timeout => io::ErrorKind::TimedOut,
            _ => io::ErrorKind::Other,
        };

        io::Error::new(error_kind, format!("ProtoError: {}", e))
    }
}

impl Clone for ProtoErrorKind {
    fn clone(&self) -> Self {
        match *self {
            ProtoErrorKind::AddrParseError => ProtoErrorKind::AddrParseError,
            ProtoErrorKind::Canceled(ref c) => ProtoErrorKind::Canceled(*c),
            ProtoErrorKind::CharacterDataTooLong(len) => ProtoErrorKind::CharacterDataTooLong(len),
            ProtoErrorKind::DnsKeyProtocolNot3(value) => ProtoErrorKind::DnsKeyProtocolNot3(value),
            ProtoErrorKind::DomainNameTooLong(len) => ProtoErrorKind::DomainNameTooLong(len),
            ProtoErrorKind::EdnsNameNotRoot(ref found) => {
                ProtoErrorKind::EdnsNameNotRoot(found.clone())
            }
            ProtoErrorKind::FromUtf8Error => ProtoErrorKind::FromUtf8Error,
            ProtoErrorKind::Io => ProtoErrorKind::Io,
            ProtoErrorKind::IncorrectRDataLengthRead(read, len) => {
                ProtoErrorKind::IncorrectRDataLengthRead(read, len)
            }
            ProtoErrorKind::LabelBytesTooLong(len) => ProtoErrorKind::LabelBytesTooLong(len),
            ProtoErrorKind::Message(msg) => ProtoErrorKind::Message(msg),
            ProtoErrorKind::Msg(ref string) => ProtoErrorKind::Msg(string.clone()),
            ProtoErrorKind::NoError => ProtoErrorKind::NoError,
            ProtoErrorKind::ParseIntError => ProtoErrorKind::ParseIntError,
            ProtoErrorKind::Timeout => ProtoErrorKind::Timeout,
            ProtoErrorKind::UnknownAlgorithmTypeValue(value) => {
                ProtoErrorKind::UnknownAlgorithmTypeValue(value)
            }
            ProtoErrorKind::UnknownDnsClassStr(ref value) => {
                ProtoErrorKind::UnknownDnsClassStr(value.clone())
            }
            ProtoErrorKind::UnknownDnsClassValue(value) => {
                ProtoErrorKind::UnknownDnsClassValue(value)
            }
            ProtoErrorKind::UnrecognizedLabelCode(value) => {
                ProtoErrorKind::UnrecognizedLabelCode(value)
            }
            ProtoErrorKind::UnrecognizedNsec3Flags(value) => {
                ProtoErrorKind::UnrecognizedNsec3Flags(value)
            }
            ProtoErrorKind::UnknownRecordTypeStr(ref value) => {
                ProtoErrorKind::UnknownRecordTypeStr(value.clone())
            }
            ProtoErrorKind::UnknownRecordTypeValue(value) => {
                ProtoErrorKind::UnknownRecordTypeValue(value)
            }
            ProtoErrorKind::UrlParsingError => ProtoErrorKind::UrlParsingError,
            ProtoErrorKind::Utf8Error => ProtoErrorKind::Utf8Error,
            ProtoErrorKind::Ring => ProtoErrorKind::Ring,
            ProtoErrorKind::SSL => ProtoErrorKind::SSL,
            ProtoErrorKind::RrsigsNotPresent(ref name, ref record_type) => {
                ProtoErrorKind::RrsigsNotPresent(name.clone(), *record_type)
            }
        }
    }
}

// TODO: replace this when https://github.com/rust-lang-nursery/error-chain/pull/163 is merged
impl Clone for ProtoError {
    fn clone(&self) -> Self {
        let cloned_kind: ProtoErrorKind = self.0.clone();

        // sadly need to convert the inner error...

        let inner_error: Option<Box<::std::error::Error + Send + 'static>> =
            (&self.1).0.as_ref().map(|e| {
                Box::new(ProtoError::from(ProtoErrorKind::Msg(format!("{}", e))))
                    as Box<::std::error::Error + Send + 'static>
            });
        ProtoError(cloned_kind, (inner_error, Arc::clone(&(self.1).1)))
    }
}

pub trait FromProtoError: From<ProtoError> + ::std::error::Error + Clone {}

impl<E> FromProtoError for E
where
    E: From<ProtoError> + ::std::error::Error + Clone,
{
}
