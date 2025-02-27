// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS client implementation for Rustls

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use std::io;
use std::net::SocketAddr;

use futures_util::TryFutureExt;
use rustls::ClientConfig;

use crate::error::ProtoError;
use crate::runtime::RuntimeProvider;
use crate::runtime::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::rustls::tls_stream::{tls_connect_with_bind_addr, tls_connect_with_future};
use crate::tcp::{DnsTcpStream, TcpClientStream};
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
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect<P: RuntimeProvider>(
    name_server: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<P::Tcp>, ProtoError>> + Send + Unpin>>,
    BufDnsStreamHandle,
) {
    tls_client_connect_with_bind_addr(name_server, None, dns_name, client_config, provider)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect_with_bind_addr<P: RuntimeProvider>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<P::Tcp>, ProtoError>> + Send + Unpin>>,
    BufDnsStreamHandle,
) {
    let (stream_future, sender) =
        tls_connect_with_bind_addr(name_server, bind_addr, dns_name, client_config, provider);

    let new_future = Box::pin(
        stream_future
            .map_ok(TcpClientStream::from_stream)
            .map_err(ProtoError::from),
    );

    (new_future, sender)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `future` - A future producing DnsTcpStream
/// * `dns_name` - The DNS name associated with a certificate
#[allow(clippy::type_complexity)]
pub fn tls_client_connect_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Arc<ClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send + Unpin>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = io::Result<S>> + Send + Unpin + 'static,
{
    let (stream_future, sender) =
        tls_connect_with_future(future, socket_addr, dns_name, client_config);

    let new_future = Box::pin(
        stream_future
            .map_ok(TcpClientStream::from_stream)
            .map_err(ProtoError::from),
    );

    (new_future, sender)
}
