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
use std::sync::Arc;

use self::rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use futures::Future;

use proto::error::ProtoError;
use proto::BufDnsStreamHandle;
use trust_dns_rustls::{tls_client_connect, TlsClientStream};

lazy_static! {
    // using the mozilla default root store
    static ref CLIENT_CONFIG: Arc<ClientConfig> = {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(&self::webpki_roots::TLS_SERVER_ROOTS);
        let versions = vec![ProtocolVersion::TLSv1_2];

        let mut client_config = ClientConfig::new();
        client_config.root_store = root_store;
        client_config.versions = versions;

        Arc::new(client_config)
    };
}

pub(crate) fn new_tls_stream(
    socket_addr: SocketAddr,
    dns_name: String,
) -> (
    Box<dyn Future<Item = TlsClientStream, Error = ProtoError> + Send>,
    BufDnsStreamHandle,
) {
    let (stream, handle) = tls_client_connect(socket_addr, dns_name, CLIENT_CONFIG.clone());
    (Box::new(stream), handle)
}
