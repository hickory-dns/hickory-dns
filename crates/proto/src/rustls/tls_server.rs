// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS server implementation for Rustls

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use rustls::{self, Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, read_one, Item};

use crate::error::{ProtoError, ProtoResult};

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert(cert_path: &Path) -> ProtoResult<Vec<Certificate>> {
    let mut cert_file = File::open(cert_path)
        .map_err(|e| format!("error opening cert file: {cert_path:?}: {e}"))?;

    let mut reader = BufReader::new(&mut cert_file);
    match certs(&mut reader) {
        Ok(certs) => Ok(certs.into_iter().map(Certificate).collect()),
        Err(_) => Err(ProtoError::from(format!(
            "failed to read certs from: {}",
            cert_path.display()
        ))),
    }
}

/// Reads a private key from a pkcs8 formatted, and possibly encoded file
///
/// ## Accepted formats
///
/// - A Sec1-encoded plaintext private key; as specified in RFC5915
/// - A DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC3447
/// - DER-encoded plaintext private key; as specified in PKCS#8/RFC5958
pub fn read_key(path: &Path) -> ProtoResult<PrivateKey> {
    let mut file = BufReader::new(File::open(path)?);

    loop {
        match read_one(&mut file)? {
            Some(Item::ECKey(key)) => return Ok(PrivateKey(key)),
            Some(Item::RSAKey(key)) => return Ok(PrivateKey(key)),
            Some(Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
            Some(_) => continue,
            None => return Err(format!("no keys available in: {}", path.display()).into()),
        };
    }
}

/// Reads a private key from a der formatted file
pub fn read_key_from_der(path: &Path) -> ProtoResult<PrivateKey> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(PrivateKey(buf))
}

/// Attempts to read a private key from a PEM formatted file.
///
/// ## Accepted formats
///
/// - DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC3447
/// - DER-encoded plaintext RSA private key; as specified in PKCS#8/RFC5958 default with openssl v3
///
/// ## Errors
///
/// Returns a [ProtoError] in either cases:
///
/// - Unable to open key at given `path`
/// - Encountered an IO error
/// - Unable to read key: either no key or no key found in the right format
pub fn read_key_from_pem(path: &Path) -> ProtoResult<PrivateKey> {
    let file = File::open(path)?;
    let mut file = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut file)? {
            None => return Err(format!("No RSA keys in file: {}", path.display()).into()),
            Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
            Some(_) => continue,
        }
    }
}

/// Construct the new Acceptor with the associated pkcs12 data
pub fn new_acceptor(
    cert: Vec<Certificate>,
    key: PrivateKey,
) -> Result<ServerConfig, rustls::Error> {
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;

    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}
