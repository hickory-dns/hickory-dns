// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-rustls")]
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::future::Future;
use rustls::{ClientConfig, RootCertStore};

use proto::error::ProtoError;
use proto::rustls::tls_client_stream::tls_client_connect_with_future;
use proto::rustls::TlsClientStream;
use proto::tcp::DnsTcpStream;
use proto::BufDnsStreamHandle;

use crate::config::TlsClientConfig;

const ALPN_H2: &[u8] = b"h2";

pub(crate) fn client_config() -> Result<Arc<ClientConfig>, ProtoError> {
    #[cfg(not(all(feature = "native-certs", not(feature = "webpki-roots"))))]
    {
        use once_cell::sync::Lazy;

        static CONFIG: Lazy<Result<Arc<ClientConfig>, ProtoError>> =
            Lazy::new(client_config_internal);
        CONFIG.clone()
    }
    #[cfg(all(feature = "native-certs", not(feature = "webpki-roots")))]
    client_config_internal()
}

fn client_config_internal() -> Result<Arc<ClientConfig>, ProtoError> {
    #[cfg_attr(
        not(any(feature = "native-certs", feature = "webpki-roots")),
        allow(unused_mut)
    )]
    let mut root_store = RootCertStore::empty();
    #[cfg(all(feature = "native-certs", not(feature = "webpki-roots")))]
    {
        use proto::error::ProtoErrorKind;

        for cert in rustls_native_certs::load_native_certs()? {
            if let Err(err) = root_store.add(&rustls::Certificate(cert.0)) {
                tracing::warn!(
                    "failed to parse certificate from native root store: {:?}",
                    &err
                );
            }
        }
        if root_store.is_empty() {
            return Err(ProtoErrorKind::NativeCerts.into());
        }
    }
    #[cfg(feature = "webpki-roots")]
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    client_config.enable_sni = false;

    client_config.alpn_protocols.push(ALPN_H2.to_vec());

    Ok(Arc::new(client_config))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: TlsClientConfig,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = io::Result<S>> + Send + Unpin + 'static,
{
    let (stream, handle) =
        tls_client_connect_with_future(future, socket_addr, dns_name, client_config.0);
    (Box::pin(stream), handle)
}
