// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! text records for storing arbitrary data
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::ProtoResult,
    rr::{RData, RecordData, RecordDataDecodable, RecordType},
    serialize::{binary::*, txt::ParseError},
};

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 3.3.14. TXT RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                   TXT-DATA                    /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
///
/// TXT RRs are used to hold descriptive text.  The semantics of the text
/// depends on the domain where it is found.
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub struct TXT {
    /// ```text
    /// TXT-DATA        One or more <character-string>s.
    /// ```
    pub txt_data: Box<[Box<[u8]>]>,
}

impl TXT {
    /// Creates a new TXT record data from bytes.
    ///
    /// Fails if any element of the iterator is longer than 255 bytes, or if the total length of
    /// all elements exceeds 65535 bytes.
    pub fn new(txt_data: impl Iterator<Item = impl Into<Box<[u8]>>>) -> Result<Self, ParseError> {
        Self::new_inner(txt_data.map(Into::into).collect::<Box<[_]>>())
    }

    /// Parse the RData from a set of Tokens
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn from_tokens<'i, I: Iterator<Item = &'i str>>(
        tokens: I,
    ) -> Result<Self, ParseError> {
        Self::new_inner(
            tokens
                .map(|s| Box::from(s.as_bytes()))
                .collect::<Box<[_]>>(),
        )
    }

    fn new_inner(txt_data: Box<[Box<[u8]>]>) -> Result<Self, ParseError> {
        let mut total = 0;
        for part in txt_data.iter() {
            total += part.len();
            if part.len() > 255 {
                return Err(ParseError::Message(
                    "TXT record must not exceed 255 octets".into(),
                ));
            }
        }

        if total > 65535 {
            return Err(ParseError::Message(
                "TXT record data must not exceed 65535 octets".into(),
            ));
        }

        Ok(Self { txt_data })
    }
}

impl BinEncodable for TXT {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        for s in &self.txt_data {
            encoder.emit_character_data(s)?;
        }

        Ok(())
    }
}

impl RecordDataDecodable<'_> for TXT {
    fn read_data(decoder: &mut BinDecoder<'_>) -> Result<Self, DecodeError> {
        let mut strings = Vec::with_capacity(1);

        while !decoder.is_empty() {
            let string = decoder.read_character_data()?.unverified(/*any data should be validate in TXT usage*/);
            strings.push(string.to_vec().into_boxed_slice());
        }
        Ok(Self {
            txt_data: strings.into_boxed_slice(),
        })
    }
}

impl RecordData for TXT {
    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::TXT(data) => Some(data),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::TXT
    }

    fn into_rdata(self) -> RData {
        RData::TXT(self)
    }
}

impl TryFrom<String> for TXT {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new_inner(Box::new([value.into_boxed_str().into()]))
    }
}

impl fmt::Display for TXT {
    /// Format a [TXT] with lossy conversion of invalid utf8.
    ///
    /// ## Case of invalid utf8
    ///
    /// Invalid utf8 will be converted to:
    /// `U+FFFD REPLACEMENT CHARACTER`, which looks like this: �
    ///
    /// Same behaviour as `alloc::string::String::from_utf8_lossy`.
    /// ```rust
    /// # use hickory_proto::rr::rdata::TXT;
    /// let first_bytes = b"Invalid utf8 <\xF0\x90\x80>.";
    /// let second_bytes = b" Valid utf8 <\xF0\x9F\xA4\xA3>";
    /// let txt = TXT::new([first_bytes.to_vec(), second_bytes.to_vec()].into_iter()).unwrap();
    ///
    /// let tested = format!("{}", txt);
    /// assert_eq!(
    ///     tested.as_bytes(),
    ///     b"Invalid utf8 <\xEF\xBF\xBD>. Valid utf8 <\xF0\x9F\xA4\xA3>",
    ///     "Utf8 lossy conversion error! Mismatch between input and expected"
    /// );
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for txt in self.txt_data.iter() {
            f.write_str(&String::from_utf8_lossy(txt))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    #[cfg(feature = "std")]
    use std::println;

    use super::*;

    #[test]
    fn test() {
        let rdata =
            TXT::new([b"Test me some".to_vec(), b"more please".to_vec()].into_iter()).unwrap();

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        #[cfg(feature = "std")]
        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = TXT::read_data(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn publish_binary_txt_record() {
        let bin_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let rdata = TXT::new([b"Test me some".to_vec(), bin_data].into_iter()).unwrap();

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(rdata.emit(&mut encoder).is_ok());
        let bytes = encoder.into_bytes();

        #[cfg(feature = "std")]
        println!("bytes: {bytes:?}");

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = TXT::read_data(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn from_tokens_string_at_limit() {
        // A single character-string of exactly 255 octets is valid.
        let token = "a".repeat(255);
        let rdata = TXT::from_tokens([token.as_str()].into_iter())
            .expect("a 255-octet character-string should be allowed");
        assert_eq!(rdata.txt_data.len(), 1);
        assert_eq!(rdata.txt_data[0].len(), 255);
    }

    #[test]
    fn from_tokens_string_over_limit() {
        // A single character-string longer than 255 octets is rejected.
        let token = "a".repeat(256);
        assert!(
            TXT::from_tokens([token.as_str()].into_iter()).is_err(),
            "a character-string longer than 255 octets should be rejected"
        );
    }

    #[test]
    fn from_tokens_many_strings_allowed() {
        // The count of character-strings is not capped at 255; only per-string
        // length and total data size are constrained.
        let tokens = vec!["a"; 256];
        let rdata = TXT::from_tokens(tokens.iter().copied())
            .expect("many short character-strings should be allowed");
        assert_eq!(rdata.txt_data.len(), 256);
    }

    #[test]
    fn from_tokens_total_data_over_limit() {
        // Total data exceeding 65535 octets is rejected, even when every
        // individual character-string is within the 255-octet limit.
        let token = "a".repeat(255);
        let tokens = vec![token.as_str(); 258]; // 258 * 255 = 65790 octets
        assert!(
            TXT::from_tokens(tokens.into_iter()).is_err(),
            "total TXT data exceeding 65535 octets should be rejected"
        );
    }
}
