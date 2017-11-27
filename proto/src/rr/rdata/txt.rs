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

use serialize::binary::*;
use error::*;

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
    txt_data: Vec<String>,
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
        TXT { txt_data: txt_data }
    }

    /// ```text
    /// TXT-DATA        One or more <character-string>s.
    /// ```
    pub fn txt_data(&self) -> &[String] {
        &self.txt_data
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> ProtoResult<TXT> {
    let data_len = decoder.len();
    let mut strings = Vec::with_capacity(1);

    while data_len - decoder.len() < rdata_length as usize {
        strings.push(decoder.read_character_data()?);
    }
    Ok(TXT::new(strings))
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, txt: &TXT) -> ProtoResult<()> {
    for s in txt.txt_data() {
        encoder.emit_character_data(s)?;
    }

    Ok(())
}

#[test]
fn test() {
    let rdata = TXT::new(vec!["Test me some".to_string(), "more please".to_string()]);

    let mut bytes = Vec::new();
    let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
    assert!(emit(&mut encoder, &rdata).is_ok());
    let bytes = encoder.into_bytes();

    println!("bytes: {:?}", bytes);

    let mut decoder: BinDecoder = BinDecoder::new(bytes);
    let read_rdata = read(&mut decoder, bytes.len() as u16);
    assert!(
        read_rdata.is_ok(),
        format!("error decoding: {:?}", read_rdata.unwrap_err())
    );
    assert_eq!(rdata, read_rdata.unwrap());
}
