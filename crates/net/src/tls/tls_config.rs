// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{io, sync::Arc};

use rustls::{ServerConfig, server::ResolvesServerCert};

pub use super::default_provider;

/// Construct a default [`ServerConfig`] for TLS over TCP, such as DoT or HTTP/2.
///
/// The returned configuration uses the safe default protocol versions and does not request client
/// certificates. `alpn` selects the ALPN, such as `b"dot"` or `b"h2"`.
/// For QUIC-based protocols, use `server_quic` instead.
pub fn server_tcp(
    alpn: &[u8],
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// Construct a default TLS [`ServerConfig`] for QUIC-based protocols, such as DoQ or HTTP/3.
///
/// The returned configuration only enables TLS 1.3, as required by QUIC, uses the given ALPN
/// protocol and does not request client certificates. `alpn` selects the ALPN, such as
/// `b"doq"` or `b"h3"`.
#[cfg(feature = "__quic")]
pub fn server_quic(alpn: &[u8], cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3 not supported") // The ring default provider is guaranteed to support TLS 1.3
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    config.alpn_protocols = vec![alpn.to_vec()];
    config
}
