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

use rustls::internal::pemfile::{certs, pkcs8_private_keys};
use rustls::{self, Certificate, PrivateKey, ServerConfig};

use trust_dns_proto::error::{ProtoError, ProtoResult};

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert(cert_path: &Path) -> ProtoResult<Vec<Certificate>> {
    let mut cert_file = File::open(&cert_path)
        .map_err(|e| format!("error opening cert file: {:?}: {}", cert_path, e))?;

    let mut reader = BufReader::new(&mut cert_file);
    certs(&mut reader).map_err(|()| {
        ProtoError::from(format!(
            "failed to read certs from: {}",
            cert_path.display()
        ))
    })
}

/// Reads a private key from a pkcs8 formatted, and possibly encoded file
pub fn read_key_from_pkcs8(path: &Path) -> ProtoResult<PrivateKey> {
    let mut file = BufReader::new(File::open(path)?);

    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut file)
        .map_err(|()| ProtoError::from(format!("failed to read keys from: {}", path.display())))?;
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

/// Construct the new Acceptor with the associated pkcs12 data
pub fn new_acceptor(
    cert: Vec<Certificate>,
    key: PrivateKey,
) -> Result<ServerConfig, rustls::TLSError> {
    let mut config = ServerConfig::new(rustls::NoClientAuth::new());
    config.set_protocols(&[b"h2".to_vec()]);
    config.set_single_cert(cert, key)?;

    Ok(config)
}
