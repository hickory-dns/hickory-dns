// Copyright 2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! OPENPGPKEY records for OpenPGP public keys
use std::fmt;

#[cfg(feature = "serde-config")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::serialize::binary::*;

/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.1)
///
/// ```text
/// The RDATA portion of an OPENPGPKEY resource record contains a single
/// value consisting of a Transferable Public Key formatted as specified
/// in [RFC4880].
/// ```
#[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct OPENPGPKEY {
    public_key: Vec<u8>,
}

impl OPENPGPKEY {
    /// Creates a new OPENPGPKEY record data.
    ///
    /// # Arguments
    ///
    /// * `public_key` - an OpenPGP Transferable Public Key. This will NOT
    ///    be checked.
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    /// The public key. This should be an OpenPGP Transferable Public Key,
    /// but this is not guaranteed.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Read the RData from the given decoder.
pub fn read(decoder: &mut BinDecoder<'_>, rdata_length: Restrict<u16>) -> ProtoResult<OPENPGPKEY> {
    let rdata_length = rdata_length.map(usize::from).unverified();
    let public_key =
        decoder.read_vec(rdata_length)?.unverified(/*we do not enforce a specific format*/);
    Ok(OPENPGPKEY::new(public_key))
}

/// Write the RData using the given encoder
pub fn emit(encoder: &mut BinEncoder<'_>, openpgpkey: &OPENPGPKEY) -> ProtoResult<()> {
    encoder.emit_vec(openpgpkey.public_key())
}

/// Parse the RData from a set of tokens.
///
/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.3)
///
/// ```text
/// 2.3.  The OPENPGPKEY RDATA Presentation Format
///
///    The RDATA Presentation Format, as visible in Zone Files [RFC1035],
///    consists of a single OpenPGP Transferable Public Key as defined in
///    Section 11.1 of [RFC4880] encoded in base64 as defined in Section 4
///    of [RFC4648].
/// ```
impl fmt::Display for OPENPGPKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&data_encoding::BASE64.encode(&self.public_key))
    }
}

// TODO test
