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

use serialize::binary::*;
use error::*;

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
    pub fn anything(&self) -> Option<&Vec<u8>> {
        self.anything.as_ref()
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder, rdata_length: u16) -> ProtoResult<NULL> {
    if rdata_length > 0 {
        let mut anything: Vec<u8> = Vec::with_capacity(rdata_length as usize);
        for _ in 0..rdata_length {
            if let Ok(byte) = decoder.pop() {
                anything.push(byte);
            } else {
                return Err(ProtoErrorKind::Message("unexpected end of input reached").into());
            }
        }

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

#[test]
pub fn test() {
    let rdata = NULL::with(vec![0, 1, 2, 3, 4, 5, 6, 7]);

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
