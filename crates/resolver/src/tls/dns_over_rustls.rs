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
use once_cell::sync::Lazy;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

use proto::error::ProtoError;
use proto::rustls::tls_client_stream::tls_client_connect_with_future;
use proto::rustls::TlsClientStream;
use proto::tcp::DnsTcpStream;
use proto::BufDnsStreamHandle;

use crate::config::TlsClientConfig;

const ALPN_H2: &[u8] = b"h2";

// using the mozilla default root store
pub(crate) static CLIENT_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
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

    Arc::new(client_config)
});

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = io::Result<S>> + Send + Unpin + 'static,
{
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );
    let (stream, handle) =
        tls_client_connect_with_future(future, socket_addr, dns_name, client_config);
    (Box::pin(stream), handle)
}
