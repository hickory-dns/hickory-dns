// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
#[cfg(feature = "native-certs")]
use tracing::warn;

pub mod tls_client_stream;
pub mod tls_server;
pub mod tls_stream;

pub use self::tls_client_stream::{
    tls_client_connect, tls_client_connect_with_bind_addr, TlsClientStream,
};
pub use self::tls_stream::{tls_connect, tls_connect_with_bind_addr, tls_from_stream, TlsStream};

#[cfg(test)]
pub(crate) mod tests;

/// Make a new [`ClientConfig`] with the default settings
pub fn client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
    #[allow(unused_mut)]
    let mut root_store = RootCertStore::empty();
    #[cfg(feature = "native-certs")]
    {
        use crate::error::ProtoErrorKind;

        let mut result = rustls_native_certs::load_native_certs();
        if let Some(err) = result.errors.pop() {
            return Err(err.into());
        }

        let (added, ignored) = root_store.add_parsable_certificates(result.certs);
        if ignored > 0 {
            warn!("failed to parse {ignored} certificate(s) from the native root store");
        }

        if added == 0 {
            return Err(ProtoErrorKind::NativeCerts.into());
        }
    }

    #[cfg(feature = "webpki-roots")]
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}
