// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

use rustls::{self, Certificate, PrivateKey, ProtocolVersion, ServerConfig};

use trust_dns_proto::error::ProtoResult;

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert(
    cert_path: &Path,
    private_key_path: &Path,
) -> ProtoResult<(Certificate, PrivateKey)> {
    let mut cert_file = File::open(&cert_path)
        .map_err(|e| format!("error opening cert file: {:?}: {}", cert_path, e))?;

    let mut cert_bytes = vec![];
    cert_file
        .read_to_end(&mut cert_bytes)
        .map_err(|e| format!("could not read cert from: {:?}: {}", cert_path, e))?;
    drop(cert_file);

    let mut key_file = File::open(&private_key_path).map_err(|e| {
        format!(
            "error opening private_key file: {:?}: {}",
            private_key_path, e
        )
    })?;

    let mut key_bytes = vec![];
    key_file.read_to_end(&mut key_bytes).map_err(|e| {
        format!(
            "could not read private_key from: {:?}: {}",
            private_key_path, e
        )
    })?;

    Ok((Certificate(cert_bytes), PrivateKey(key_bytes)))
}

/// Construct the new Acceptor with the associated pkcs12 data
pub fn new_acceptor(cert: Certificate, key: PrivateKey) -> Result<ServerConfig, rustls::TLSError> {
    let mut config = ServerConfig::new(rustls::NoClientAuth::new());
    config.set_protocols(&["h2".to_string()]);
    config.set_single_cert(vec![cert], key)?;

    Ok(config)
}
