// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS server implementation for Rustls

use std::path::Path;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

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
