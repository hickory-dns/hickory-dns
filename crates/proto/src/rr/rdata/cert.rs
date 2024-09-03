// Copyright 2024 Brian Taber <btaber@zsd.systems>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! CERT record type for storing certificates in DNS
use std::fmt;

#[cfg(feature = "serde")]
use serde::{ Deserialize, Serialize };

use crate::{
    error::*,
    rr::{ RData, RecordData, RecordDataDecodable, RecordType },
    serialize::binary::*,
};

/// [RFC 4398, Storing Certificates in DNS, November 1987][rfc4398]
/// https://tools.ietf.org/html/rfc4398
///
/// ```text
///
/// The CERT resource record (RR) has the structure given below.  Its RR
/// type code is 37.
///
///    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             type              |             key tag           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   algorithm   |                                               /
/// +---------------+            certificate or CRL                 /
/// /                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// ```
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CERT {
    cert_type: u32,
    key_tag: u32,
    algorithm: u32,
    cert_data: Vec<u8>,
}

impl CERT {
    /// Construct a new CERT RData
    pub const fn new() -> Self {
        Self {
            cert_type: 0,
            key_tag: 0,
            algorithm: 0,
            cert_data: vec![],
        }
    }

    /// Constructs a new CERT RData with the associated data
    pub fn with(cert_data: Vec<u8>) -> Self {
        let cert_type: u32 = ((cert_data[0] as u32) << 8) | (cert_data[1] as u32);
        let key_tag: u32 = ((cert_data[2] as u32) << 8) | (cert_data[3] as u32);
        let algorithm: u32 = cert_data[4].into();
        let cert_data: Vec<u8> = cert_data[5..].to_vec();

        Self {
            cert_type,
            key_tag,
            algorithm,
            cert_data,
        }
    }

    /// Returns the CERT type
    pub fn cert_type(&self) -> u32 {
        self.cert_type
    }

    /// Returns the CERT key tag
    pub fn key_tag(&self) -> u32 {
        self.key_tag
    }

    /// Returns the CERT algorithm
    pub fn algorithm(&self) -> u32 {
        self.algorithm
    }

    /// Returns the CERT record data
    pub fn cert_data(&self) -> Vec<u8> {
        self.cert_data.clone()
    }

    /// Returns the CERT (Base64)
    pub fn cert_base64(&self) -> String {
        data_encoding::BASE64.encode(&self.cert_data).clone()
    }
}

impl BinEncodable for CERT {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u32(self.cert_type)?;
        encoder.emit_u32(self.key_tag)?;
        encoder.emit_u32(self.algorithm)?;
        encoder.emit_vec(&self.cert_data)?;

        Ok(())
    }
}

impl<'r> RecordDataDecodable<'r> for CERT {
    fn read_data(decoder: &mut BinDecoder<'r>, length: Restrict<u16>) -> ProtoResult<Self> {
        let rdata_length = length.map(|u| u as usize).unverified();
        if rdata_length > 0 {
            let cert_data = decoder.read_vec(rdata_length)?.unverified(/*any byte array is good*/);
            Ok(Self::with(cert_data))
        } else {
            Ok(Self::new())
        }
    }
}

impl RecordData for CERT {
    fn try_from_rdata(data: RData) -> Result<Self, RData> {
        match data {
            RData::CERT(data) => Ok(data),
            _ => Err(data),
        }
    }

    fn try_borrow(data: &RData) -> Option<&Self> {
        match data {
            RData::CERT(data) => Some(data),
            _ => None,
        }
    }

    fn record_type(&self) -> RecordType {
        RecordType::CERT
    }

    fn into_rdata(self) -> RData {
        RData::CERT(self)
    }
}

impl fmt::Display for CERT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let cert_data = &data_encoding::BASE64.encode(&self.cert_data);

        write!(
            f,
            "{cert_type} {key_tag} {algorithm} {cert_data}",
            cert_type = &self.cert_type,
            key_tag = &self.key_tag,
            algorithm = &self.algorithm,
            cert_data = &cert_data
        )?;

        Ok(())
    }
}
