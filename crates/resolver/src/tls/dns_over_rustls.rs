// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-rustls")]
#![allow(dead_code)]

extern crate rustls;
extern crate webpki_roots;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use self::rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use futures::Future;

use proto::error::ProtoError;
use proto::BufDnsStreamHandle;
use trust_dns_rustls::{tls_client_connect, TlsClientStream};

use crate::config::TlsClientConfig;

const ALPN_H2: &[u8] = b"h2";

lazy_static! {
    // using the mozilla default root store
    pub(crate) static ref CLIENT_CONFIG: Arc<ClientConfig> = {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(&self::webpki_roots::TLS_SERVER_ROOTS);
        let versions = vec![ProtocolVersion::TLSv1_2];

        let mut client_config = ClientConfig::new();
        client_config.root_store = root_store;
        client_config.versions = versions;
        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        Arc::new(client_config)
    };
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream(
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream, ProtoError>> + Send>>,
    BufDnsStreamHandle,
) {
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );
    let (stream, handle) = tls_client_connect(socket_addr, dns_name, client_config);
    (Box::pin(stream), handle)
}
