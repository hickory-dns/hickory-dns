// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

use alloc::sync::Arc;

#[cfg(not(feature = "rustls-platform-verifier"))]
use rustls::RootCertStore;
use rustls::{
    ClientConfig,
    crypto::{self, CryptoProvider},
};
#[cfg(feature = "rustls-platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;

pub mod tls_client_stream;
pub mod tls_stream;

pub use self::tls_client_stream::{
    TlsClientStream, tls_client_connect, tls_client_connect_with_bind_addr,
};
pub use self::tls_stream::{TlsStream, tls_connect, tls_connect_with_bind_addr, tls_from_stream};

/// Make a new [`ClientConfig`] with the default settings
pub fn client_config() -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap();

    #[cfg(feature = "rustls-platform-verifier")]
    let builder = builder.with_platform_verifier();
    #[cfg(not(feature = "rustls-platform-verifier"))]
    let builder = builder.with_root_certificates({
        #[cfg_attr(not(feature = "webpki-roots"), allow(unused_mut))]
        let mut root_store = RootCertStore::empty();
        #[cfg(feature = "webpki-roots")]
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    });

    builder.with_no_client_auth()
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub fn default_provider() -> CryptoProvider {
    crypto::aws_lc_rs::default_provider()
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(feature = "tls-ring")]
pub fn default_provider() -> CryptoProvider {
    crypto::ring::default_provider()
}
