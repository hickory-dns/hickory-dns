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

use openssl::dh::Dh;
use openssl::pkcs12::*;
use openssl::ssl::{self, SslAcceptor, SslMethod, SslMode, SslOptions, SslVerifyMode};

pub use openssl::pkcs12::ParsedPkcs12;
pub use tokio_openssl::SslAcceptorExt;

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert(path: &Path, password: Option<&str>) -> Result<ParsedPkcs12, String> {
    let mut file = File::open(&path)
        .map_err(|e| format!("error opening pkcs12 cert file: {:?}: {}", path, e))?;

    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes)
        .map_err(|e| format!("could not read pkcs12 key from: {:?}: {}", path, e))?;
    let pkcs12 = Pkcs12::from_der(&key_bytes)
        .map_err(|e| format!("badly formated pkcs12 key from: {:?}: {}", path, e))?;
    pkcs12
        .parse(password.unwrap_or(""))
        .map_err(|e| format!("failed to open pkcs12 from: {:?}: {}", path, e))
}

/// Construct the new Acceptor with the associated pkcs12 data
pub fn new_acceptor(pkcs12: &ParsedPkcs12) -> io::Result<SslAcceptor> {
    // TODO: make an internal error type with conversions
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;

    builder.set_private_key(&pkcs12.pkey)?;
    builder.set_certificate(&pkcs12.cert)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_options(
        SslOptions::NO_COMPRESSION
            | SslOptions::NO_SSLV2
            | SslOptions::NO_SSLV3
            | SslOptions::NO_TLSV1
            | SslOptions::NO_TLSV1_1,
    );

    if let Some(ref chain) = pkcs12.chain {
        for cert in chain {
            builder.add_extra_chain_cert(cert.to_owned())?;
        }
    }

    // validate our certificate and private key match
    builder.check_private_key()?;

    Ok(builder.build())
}
