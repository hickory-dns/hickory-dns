use openssl::pkcs12::*;
use openssl::ssl;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

pub use openssl::pkcs12::ParsedPkcs12;
pub use tokio_openssl::SslAcceptorExt;

pub fn read_cert(path: &Path, password: Option<&str>) -> Result<ParsedPkcs12, String> {
    let mut file = File::open(&path).map_err(|e| {
        format!("error opening pkcs12 cert file: {:?}: {}", path, e)
    })?;

    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).map_err(|e| {
        format!("could not read pkcs12 key from: {:?}: {}", path, e)
    })?;
    let pkcs12 = Pkcs12::from_der(&key_bytes).map_err(|e| {
        format!("badly formated pkcs12 key from: {:?}: {}", path, e)
    })?;
    pkcs12
        .parse(password.unwrap_or(""))
        .map_err(|e| format!("failed to open pkcs12 from: {:?}: {}", path, e))
}


pub fn new_acceptor(pkcs12: &ParsedPkcs12) -> io::Result<SslAcceptor> {
    let mut builder = SslAcceptorBuilder::mozilla_modern(
        SslMethod::tls(),
        &pkcs12.pkey,
        &pkcs12.cert,
        &pkcs12.chain,
    ).map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("tls error: {}", e),
        )
    })?;

    // mut block
    {
        let ssl_context_bldr = builder.builder_mut();

        ssl_context_bldr.set_options(
            ssl::SSL_OP_NO_SSLV2 | ssl::SSL_OP_NO_SSLV3 | ssl::SSL_OP_NO_TLSV1
                | ssl::SSL_OP_NO_TLSV1_1,
        );
    }

    Ok(builder.build())
}
