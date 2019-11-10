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

//! null record type, generally not used except as an internal tool for representing null data

use crate::error::*;
use crate::serialize::binary::*;

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987](https://tools.ietf.org/html/rfc1035)
///
/// ```text
/// 3.3.10. NULL RDATA format (EXPERIMENTAL)
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                  <anything>                   /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// Anything at all may be in the RDATA field so long as it is 65535 octets
/// or less.
///
/// NULL records cause no additional section processing.  NULL RRs are not
/// allowed in master files.  NULLs are used as placeholders in some
/// experimental extensions of the DNS.
/// ```
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct NULL {
    anything: Option<Vec<u8>>,
}

impl NULL {
    /// Construct a new NULL RData
    pub fn new() -> NULL {
        Default::default()
    }

    /// Constructs a new NULL RData with the associated data
    pub fn with(anything: Vec<u8>) -> NULL {
        NULL {
            anything: Some(anything),
        }
    }

    /// Returns the buffer stored in the NULL
    pub fn anything(&self) -> Option<&[u8]> {
        self.anything.as_ref().map(|bytes| &bytes[..])
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: Restrict<u16>) -> ProtoResult<NULL> {
    let rdata_length = rdata_length.map(|u| u as usize).unverified(/*any u16 is valid*/);
    if rdata_length > 0 {
        let anything = decoder.read_vec(rdata_length)?.unverified(/*any byte array is good*/);
        Ok(NULL::with(anything))
    } else {
        Ok(NULL::new())
    }
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder, nil: &NULL) -> ProtoResult<()> {
    if let Some(anything) = nil.anything() {
        for b in anything.iter() {
            encoder.emit(*b)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    pub fn test() {
        let rdata = NULL::with(vec![0, 1, 2, 3, 4, 5, 6, 7]);

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
