// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-rustls")]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::future::Future;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

use proto::error::ProtoError;
use proto::rustls::{tls_client_connect_with_bind_addr, TlsClientStream};
use proto::BufDnsStreamHandle;

use crate::config::TlsClientConfig;
use crate::name_server::RuntimeProvider;

const ALPN_H2: &[u8] = b"h2";

lazy_static! {
    // using the mozilla default root store
    pub(crate) static ref CLIENT_CONFIG: Arc<ClientConfig> = {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
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

        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        Arc::new(client_config)
    };
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream<R: RuntimeProvider>(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<R::Tcp>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
) {
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );
    let (stream, handle) =
        tls_client_connect_with_bind_addr(socket_addr, bind_addr, dns_name, client_config);
    (Box::pin(stream), handle)
}
