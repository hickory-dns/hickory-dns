//! [RFC 8945] secret key transaction authentication for DNS (TSIG)
//!
//! Contains support types to allow configuring DNS implementations under test
//! with TSIG key material.
//!
//! [RFC 8945]: https://www.rfc-editor.org/rfc/rfc8945.html

use std::fmt::{self, Display, Formatter};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::Serialize;

/// A TSIG key configuration
#[derive(Clone)]
pub struct TsigKey {
    /// The name identifying the key
    pub name: String,
    /// The key algorithm to use
    pub algorithm: TsigAlgorithm,
    /// The shared symmetric secret key material
    pub secret_key: Vec<u8>,
}

impl TsigKey {
    pub fn encoded_secret_key(&self) -> String {
        BASE64_STANDARD.encode(&self.secret_key)
    }

    pub(crate) fn template(&self) -> TsigKeyTemplate {
        TsigKeyTemplate {
            name: self.name.to_owned(),
            algorithm: self.algorithm.to_string(),
            secret_key: self.encoded_secret_key(),
        }
    }
}

/// Supported TSIG algorithms
///
/// Note: this is a subset of all defined algorithms[^1] tailored to what hickory-dns
/// currently supports.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc8945.html#section-6>
#[derive(Clone, Copy)]
pub enum TsigAlgorithm {
    /// HMAC with SHA-256
    HmacSha256,
    /// HMAC with SHA-384
    HmacSha384,
    /// HMAC with SHA-512
    HmacSha512,
}

impl Display for TsigAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        })
    }
}

/// Serializable TsigKey for template rendering
#[derive(Serialize)]
pub(crate) struct TsigKeyTemplate {
    name: String,
    algorithm: String,
    secret_key: String,
}
