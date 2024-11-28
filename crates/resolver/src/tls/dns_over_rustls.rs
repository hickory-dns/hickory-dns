// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-rustls")]
#![allow(dead_code)]

use std::future;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use once_cell::sync::Lazy;
use rustls::ClientConfig;

use crate::proto::rustls::tls_client_stream::tls_client_connect_with_future;
use crate::proto::rustls::{client_config, TlsClientStream};
use crate::proto::tcp::DnsTcpStream;
use crate::proto::BufDnsStreamHandle;
use crate::proto::ProtoError;

pub(crate) static CLIENT_CONFIG: Lazy<Result<Arc<ClientConfig>, ProtoError>> = Lazy::new(|| {
    let mut config = client_config().unwrap();

    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    config.enable_sni = false;

    Ok(Arc::new(config))
});

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = io::Result<S>> + Send + Unpin + 'static,
{
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(err) => {
                return (
                    Box::pin(future::ready(Err(err))),
                    BufDnsStreamHandle::new(socket_addr).0,
                )
            }
        }
    };
    let (stream, handle) =
        tls_client_connect_with_future(future, socket_addr, dns_name, client_config);
    (Box::pin(stream), handle)
}
