// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS server implementation for Rustls

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{self, ServerConfig};

use crate::error::{ProtoError, ProtoResult};

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert(cert_path: &Path) -> ProtoResult<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(cert_path)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .map_err(|_| {
            ProtoError::from(format!(
                "failed to read certs from: {}",
                cert_path.display()
            ))
        })
}

/// Reads a private key from a PEM-encoded file
///
/// ## Accepted formats
///
/// - A Sec1-encoded plaintext private key; as specified in RFC5915
/// - A DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC3447
/// - DER-encoded plaintext private key; as specified in PKCS#8/RFC5958
///
/// ## Errors
///
/// Returns a [ProtoError] in either cases:
///
/// - Unable to open key at given `path`
/// - Encountered an IO error
/// - Unable to read key: either no key or no key found in the right format
pub fn read_key(path: &Path) -> ProtoResult<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|_| ProtoError::from(format!("failed to read key from: {}", path.display())))
}

/// Reads a private key from a DER-encoded file
///
/// ## Accepted formats
///
/// - A Sec1-encoded plaintext private key; as specified in RFC5915
/// - A DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC3447
/// - DER-encoded plaintext private key; as specified in PKCS#8/RFC5958
///
/// ## Errors
///
/// Returns a [ProtoError] in either cases:
///
/// - Unable to open key at given `path`
/// - Encountered an IO error
/// - Unable to read key: either no key or no key found in the right format
pub fn read_key_from_der(path: &Path) -> ProtoResult<PrivateKeyDer<'static>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(PrivateKeyDer::try_from(buf)?)
}

/// Construct the new Acceptor with the associated pkcs12 data
pub fn new_acceptor(
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert, key)?;

    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}
