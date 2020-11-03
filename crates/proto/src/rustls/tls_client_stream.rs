// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS client implementation for Rustls

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::TryFutureExt;
use rustls::ClientConfig;

use crate::error::ProtoError;
use crate::iocompat::AsyncIoStdAsTokio;
use crate::iocompat::AsyncIoTokioAsStd;
use crate::rustls::tls_stream::tls_connect_with_bind_addr;
use crate::tcp::{Connect, TcpClientStream};
use crate::xfer::BufDnsStreamHandle;

/// Type of TlsClientStream used with Rustls
pub type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>>>;

/// Creates a new TlsStream to the specified name_server
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect<S: Connect>(
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send + Unpin>>,
    BufDnsStreamHandle,
) {
    tls_client_connect_with_bind_addr(name_server, None, dns_name, client_config)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect_with_bind_addr<S: Connect>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send + Unpin>>,
    BufDnsStreamHandle,
) {
    let (stream_future, sender) =
        tls_connect_with_bind_addr(name_server, bind_addr, dns_name, client_config);

    let new_future = Box::pin(
        stream_future
            .map_ok(TcpClientStream::from_stream)
            .map_err(ProtoError::from),
    );

    (new_future, sender)
}
