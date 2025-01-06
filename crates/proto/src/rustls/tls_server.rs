// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS server implementation for Rustls

use std::path::Path;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
