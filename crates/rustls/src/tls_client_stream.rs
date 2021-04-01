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

use trust_dns_proto::error::ProtoError;
use trust_dns_proto::iocompat::AsyncIoStdAsTokio;
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_proto::tcp::{Connect, TcpClientStream};
use trust_dns_proto::xfer::BufDnsStreamHandle;

use crate::tls_stream::tls_connect;

/// Type of TlsClientStream used with Rustls
pub type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>>>;

/// Creates a new TlsStream to the specified name_server
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
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
    let (stream_future, sender) = tls_connect(name_server, dns_name, client_config);

    let new_future = Box::pin(
        stream_future
            .map_ok(TcpClientStream::from_stream)
            .map_err(ProtoError::from),
    );

    (new_future, sender)
}
