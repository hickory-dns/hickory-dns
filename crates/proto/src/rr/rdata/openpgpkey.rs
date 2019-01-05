// TODO license header

//! OPENPGPKEY records for OpenPGP public keys

use error::*;
use serialize::binary::*;

/// [RFC 7929](https://tools.ietf.org/html/rfc7929#section-2.1)
///
/// ```text
/// The RDATA portion of an OPENPGPKEY resource record contains a single
/// value consisting of a Transferable Public Key formatted as specified
/// in [RFC4880].
/// ```
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
        OPENPGPKEY { public_key }
    }

    /// The public key. This should be an OpenPGP Transferable Public Key,
    /// but this is not guaranteed.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Read the RData from the given decoder.
pub fn read(decoder: &mut BinDecoder, rdata_length: Restrict<u16>) -> ProtoResult<OPENPGPKEY> {
    let rdata_length = rdata_length.map(usize::from).unverified();
    let public_key =
        decoder.read_vec(rdata_length)?.unverified(/*we do not enforce a specific format*/);
    Ok(OPENPGPKEY::new(public_key))
}

/// Write the RData using the given encoder
pub fn emit(encoder: &mut BinEncoder, openpgpkey: &OPENPGPKEY) -> ProtoResult<()> {
    encoder.emit_vec(openpgpkey.public_key())
}

// TODO test
