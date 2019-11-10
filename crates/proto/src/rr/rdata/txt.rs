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

//! text records for storing arbitrary data

use std::slice::Iter;

use crate::error::*;
use crate::serialize::binary::*;

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
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TXT {
    txt_data: Box<[Box<[u8]>]>,
}

impl TXT {
    /// Creates a new TXT record data.
    ///
    /// # Arguments
    ///
    /// * `txt_data` - the set of strings which make up the txt_data.
    ///
    /// # Return value
    ///
    /// The new TXT record data.
    pub fn new(txt_data: Vec<String>) -> TXT {
        TXT {
            txt_data: txt_data
                .into_iter()
                .map(|s| s.as_bytes().to_vec().into_boxed_slice())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    /// ```text
    /// TXT-DATA        One or more <character-string>s.
    /// ```
    pub fn txt_data(&self) -> &[Box<[u8]>] {
        &self.txt_data
    }

    /// Returns an iterator over the arrays in the txt data
    pub fn iter(&self) -> Iter<Box<[u8]>> {
        self.txt_data.iter()
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: Restrict<u16>) -> ProtoResult<TXT> {
    let data_len = decoder.len();
    let mut strings = Vec::with_capacity(1);

    // no unsafe usage of rdata length after this point
    let rdata_length =
        rdata_length.map(|u| u as usize).unverified(/*used as a higher bound, safely*/);
    while data_len - decoder.len() < rdata_length {
        let string =
            decoder.read_character_data()?.unverified(/*any data should be validate in TXT usage*/);
        strings.push(string.to_vec().into_boxed_slice());
    }
    Ok(TXT {
        txt_data: strings.into_boxed_slice(),
    })
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, txt: &TXT) -> ProtoResult<()> {
    for s in txt.txt_data() {
        encoder.emit_character_data(s)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        let rdata = TXT::new(vec!["Test me some".to_string(), "more please".to_string()]);

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder = BinDecoder::new(bytes);
        let restrict = Restrict::new(bytes.len() as u16);
        let read_rdata = read(&mut decoder, restrict).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
