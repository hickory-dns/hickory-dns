// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HINFO record for storing host information

use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::serialize::binary::*;

/// [RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION, November 1987][rfc1035]
///
/// ```text
/// 3.3.2. HINFO RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                      CPU                      /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                       OS                      /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// CPU             A <character-string> which specifies the CPU type.
///
/// OS              A <character-string> which specifies the operating
///                 system type.
///
/// Standard values for CPU and OS can be found in [RFC-1010].
///
/// HINFO records are used to acquire general information about a host.  The
/// main use is for protocols such as FTP that can use special procedures
/// when talking between machines or operating systems of the same type.
/// ```
///
/// [rfc1035]: https://tools.ietf.org/html/rfc1035
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct HINFO {
    cpu: Box<[u8]>,
    os: Box<[u8]>,
}

impl HINFO {
    /// Creates a new HINFO record data.
    ///
    /// # Arguments
    ///
    /// * `cpu` - A <character-string> which specifies the CPU type.
    /// * `os` - A <character-string> which specifies the operating system type.
    ///
    /// # Return value
    ///
    /// The new HINFO record data.
    pub fn new(cpu: String, os: String) -> Self {
        Self {
            cpu: cpu.into_bytes().into_boxed_slice(),
            os: os.into_bytes().into_boxed_slice(),
        }
    }

    /// Creates a new HINFO record data from bytes.
    /// Allows creating binary record data.
    ///
    /// # Arguments
    ///
    /// * `cpu` - A <character-string> which specifies the CPU type.
    /// * `os` - A <character-string> which specifies the operating system type.
    ///
    /// # Return value
    ///
    /// The new HINFO record data.
    pub fn from_bytes(cpu: Box<[u8]>, os: Box<[u8]>) -> Self {
        Self { cpu, os }
    }

    /// A <character-string> which specifies the CPU type.
    pub fn cpu(&self) -> &[u8] {
        &self.cpu
    }

    /// A <character-string> which specifies the operating system type.
    pub fn os(&self) -> &[u8] {
        &self.os
    }
}

/// Read the RData from the given Decoder
pub fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<HINFO> {
    let cpu = decoder.read_character_data()?
        .unverified(/*any data should be validate in HINFO CPU usage*/)
        .to_vec()
        .into_boxed_slice();
    let os = decoder.read_character_data()?
        .unverified(/*any data should be validate in HINFO OS usage*/)
        .to_vec()
        .into_boxed_slice();

    Ok(HINFO { cpu, os })
}

/// Write the RData from the given Decoder
pub fn emit(encoder: &mut BinEncoder<'_>, hinfo: &HINFO) -> ProtoResult<()> {
    encoder.emit_character_data(&hinfo.cpu)?;
    encoder.emit_character_data(&hinfo.os)?;

    Ok(())
}

/// [RFC 1033](https://tools.ietf.org/html/rfc1033), DOMAIN OPERATIONS GUIDE, November 1987
///
/// ```text
/// HINFO (Host Info)
///
///            <host>   [<ttl>] [<class>]   HINFO   <hardware>   <software>
///
///    The HINFO record gives information about a particular host.  The data
///    is two strings separated by whitespace.  The first string is a
///    hardware description and the second is software.  The hardware is
///    usually a manufacturer name followed by a dash and model designation.
///    The software string is usually the name of the operating system.
///
///    Official HINFO types can be found in the latest Assigned Numbers RFC,
///    the latest of which is RFC-1010.  The Hardware type is called the
///    Machine name and the Software type is called the System name.
///
///    Some sample HINFO records:
///
///            SRI-NIC.ARPA.           HINFO   DEC-2060 TOPS20
///            UCBARPA.Berkeley.EDU.   HINFO   VAX-11/780 UNIX
/// ```
impl fmt::Display for HINFO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{cpu} {os}",
            cpu = &String::from_utf8_lossy(&self.cpu),
            os = &String::from_utf8_lossy(&self.os)
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::dbg_macro, clippy::print_stdout)]

    use super::*;

    #[test]
    fn test() {
        let rdata = HINFO::new("cpu".to_string(), "os".to_string());

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }

    #[test]
    fn test_binary() {
        let bin_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let rdata = HINFO::from_bytes(
            b"cpu".to_vec().into_boxed_slice(),
            bin_data.into_boxed_slice(),
        );

        let mut bytes = Vec::new();
        let mut encoder: BinEncoder<'_> = BinEncoder::new(&mut bytes);
        assert!(emit(&mut encoder, &rdata).is_ok());
        let bytes = encoder.into_bytes();

        println!("bytes: {:?}", bytes);

        let mut decoder: BinDecoder<'_> = BinDecoder::new(bytes);
        let read_rdata = read(&mut decoder).expect("Decoding error");
        assert_eq!(rdata, read_rdata);
    }
}
