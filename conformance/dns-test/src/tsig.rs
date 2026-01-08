//! [RFC 8945] secret key transaction authentication for DNS (TSIG)
//!
//! Contains support types to allow configuring DNS implementations under test
//! with TSIG key material.
//!
//! [RFC 8945]: https://www.rfc-editor.org/rfc/rfc8945.html

use base64::{Engine, prelude::BASE64_STANDARD};
use serde::{Serialize, Serializer};

/// A TSIG key configuration
#[derive(Clone, Serialize)]
pub struct TsigKey {
    /// The name identifying the key
    pub name: String,
    /// The key algorithm to use
    pub algorithm: TsigAlgorithm,
    /// The shared symmetric secret key material
    pub secret_key: TsigSecretKey,
}

/// Supported TSIG algorithms
///
/// Note: this is a subset of all defined algorithms[^1] tailored to what hickory-dns
/// currently supports.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc8945.html#section-6>
#[derive(Clone, Copy, Serialize)]
pub enum TsigAlgorithm {
    /// HMAC with SHA-256
    #[serde(rename(serialize = "hmac-sha256"))]
    HmacSha256,
    /// HMAC with SHA-384
    #[serde(rename(serialize = "hmac-sha384"))]
    HmacSha384,
    /// HMAC with SHA-512
    #[serde(rename(serialize = "hmac-sha512"))]
    HmacSha512,
}

/// Shared symmetric secret key material for `TsigKey`
#[derive(Clone)]
pub struct TsigSecretKey(pub Vec<u8>);

impl Serialize for TsigSecretKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_STANDARD.encode(&self.0))
    }
}
