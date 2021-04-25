// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS server implementations for OpenSSL

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

use crate::error::{ProtoError, ProtoResult};
use openssl::ssl::{SslAcceptor, SslMethod, SslOptions, SslVerifyMode};

pub use openssl::pkcs12::{ParsedPkcs12, Pkcs12};
pub use openssl::pkey::{PKey, Private};
pub use openssl::stack::Stack;
pub use openssl::x509::X509;

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
#[allow(clippy::type_complexity)]
pub fn read_cert_pkcs12(
    path: &Path,
    password: Option<&str>,
) -> ProtoResult<((X509, Option<Stack<X509>>), PKey<Private>)> {
    let mut file = File::open(&path).map_err(|e| {
        ProtoError::from(format!(
            "error opening pkcs12 cert file: {}: {}",
            path.display(),
            e
        ))
    })?;

    let mut pkcs12_bytes = vec![];
    file.read_to_end(&mut pkcs12_bytes).map_err(|e| {
        ProtoError::from(format!(
            "could not read pkcs12 from: {}: {}",
            path.display(),
            e
        ))
    })?;
    let pkcs12 = Pkcs12::from_der(&pkcs12_bytes).map_err(|e| {
        ProtoError::from(format!(
            "badly formatted pkcs12 from: {}: {}",
            path.display(),
            e
        ))
    })?;
    let parsed = pkcs12.parse(password.unwrap_or("")).map_err(|e| {
        ProtoError::from(format!(
            "failed to open pkcs12 from: {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(((parsed.cert, parsed.chain), parsed.pkey))
}

/// Read the certificate from the specified path.
///
/// If the password is specified, then it will be used to decode the Certificate
pub fn read_cert_pem(path: &Path) -> ProtoResult<(X509, Option<Stack<X509>>)> {
    let mut file = File::open(&path).map_err(|e| {
        ProtoError::from(format!(
            "error opening cert file: {}: {}",
            path.display(),
            e
        ))
    })?;

    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).map_err(|e| {
        ProtoError::from(format!(
            "could not read cert key from: {}: {}",
            path.display(),
            e
        ))
    })?;

    let cert_chain = X509::stack_from_pem(&key_bytes)?;
    let cert_count = cert_chain.len();
    let mut iter = cert_chain.into_iter();

    let cert = match iter.next() {
        None => {
            return Err(ProtoError::from(format!(
                "no certs read from file: {}",
                path.display()
            )))
        }
        Some(cert) => cert,
    };

    if cert_count < 1 {
        Ok((cert, None))
    } else {
        let mut stack = Stack::<X509>::new()?;
        for c in iter {
            stack.push(c)?;
        }
        Ok((cert, Some(stack)))
    }
}

/// Reads a private key from a pkcs8 formatted, and possibly encoded file
pub fn read_key_from_pkcs8(path: &Path, password: Option<&str>) -> ProtoResult<PKey<Private>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    match password.map(str::as_bytes) {
        Some(password) => {
            PKey::private_key_from_pkcs8_passphrase(&buf, password).map_err(Into::into)
        }
        None => PKey::private_key_from_pkcs8_passphrase(&buf, &[0_u8; 0]).map_err(Into::into),
    }
}

/// Reads a private key from a der formatted file
pub fn read_key_from_der(path: &Path) -> ProtoResult<PKey<Private>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    PKey::private_key_from_der(&buf).map_err(Into::into)
}

/// Construct the new Acceptor with the associated pkcs12 data
pub fn new_acceptor(
    cert: X509,
    chain: Option<Stack<X509>>,
    key: PKey<Private>,
) -> io::Result<SslAcceptor> {
    // TODO: make an internal error type with conversions
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;

    builder.set_private_key(&key)?;
    builder.set_certificate(&cert)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_options(
        SslOptions::NO_COMPRESSION
            | SslOptions::NO_SSLV2
            | SslOptions::NO_SSLV3
            | SslOptions::NO_TLSV1
            | SslOptions::NO_TLSV1_1,
    );

    if let Some(ref chain) = chain {
        for cert in chain {
            builder.add_extra_chain_cert(cert.to_owned())?;
        }
    }

    // validate our certificate and private key match
    builder.check_private_key()?;

    Ok(builder.build())
}
