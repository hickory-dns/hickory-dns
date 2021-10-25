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

use log::warn;
use rustls::{self, Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

use crate::error::{ProtoError, ProtoResult};

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert(cert_path: &Path) -> ProtoResult<Vec<Certificate>> {
    let mut cert_file = File::open(&cert_path)
        .map_err(|e| format!("error opening cert file: {:?}: {}", cert_path, e))?;

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
pub fn read_key_from_pkcs8(path: &Path) -> ProtoResult<PrivateKey> {
    let mut file = BufReader::new(File::open(path)?);

    let mut keys = match pkcs8_private_keys(&mut file) {
        Ok(keys) => keys.into_iter().map(PrivateKey).collect::<Vec<_>>(),
        Err(_) => {
            return Err(ProtoError::from(format!(
                "failed to read keys from: {}",
                path.display()
            )))
        }
    };

    match keys.len() {
        0 => return Err(format!("no keys available in: {}", path.display()).into()),
        1 => (),
        _ => warn!(
            "ignoring other than the first key in file: {}",
            path.display()
        ),
    }

    Ok(keys.swap_remove(0))
}

/// Reads a private key from a der formatted file
pub fn read_key_from_der(path: &Path) -> ProtoResult<PrivateKey> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(PrivateKey(buf))
}

/// Reads a private key from a pem formatted file
pub fn read_key_from_pem(path: &Path) -> ProtoResult<PrivateKey> {
    let file = File::open(path)?;
    let mut file = BufReader::new(file);

    let mut keys = rustls_pemfile::rsa_private_keys(&mut file)
        .map_err(|_| format!("Error reading RSA key from: {}", path.display()))?;
    let key = keys
        .pop()
        .ok_or_else(|| format!("No RSA keys in file: {}", path.display()))?;

    Ok(PrivateKey(key))
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
