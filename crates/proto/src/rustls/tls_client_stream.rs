// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS client implementation for Rustls

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::net::SocketAddr;
use std::io;

use futures_util::future::BoxFuture;
use rustls::{ClientConfig, pki_types::ServerName};

use crate::runtime::RuntimeProvider;
use crate::rustls::tls_stream::{tls_connect_with_bind_addr, tls_connect_with_future};
use crate::tcp::TcpClientStream;
use crate::xfer::BufDnsStreamHandle;

/// Type of TlsClientStream used with Rustls
pub type TlsClientStream<T> = TcpClientStream<T>;

/// Creates a new TlsClientStream to the specified name_server
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `server_name` - The DNS name associated with a certificate
/// * `client_config` - Rustls client TLS configuration
/// * `provider` - Async runtime provider, for I/O and timers
#[allow(clippy::type_complexity)]
pub fn tls_client_connect<P: RuntimeProvider>(
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
) {
    tls_client_connect_with_bind_addr(name_server, None, server_name, client_config, provider)
}

/// Creates a new TlsClientStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `name_server` - IP and Port for the remote DNS resolver
/// * `bind_addr` - IP and port to connect from
/// * `server_name` - The DNS name associated with a certificate
/// * `client_config` - Rustls client TLS configuration
/// * `provider` - Async runtime provider, for I/O and timers
#[allow(clippy::type_complexity)]
pub fn tls_client_connect_with_bind_addr<P: RuntimeProvider>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
) {
    let (stream_future, sender) =
        tls_connect_with_bind_addr(name_server, bind_addr, server_name, client_config, provider);

    let new_future = Box::pin(async { Ok(TcpClientStream::from_stream(stream_future.await?)) });

    (new_future, sender)
}

/// Creates a new TlsClientStream from an existing TCP connection future.
///
/// # Arguments
///
/// * `future` - A future producing a TCP connection
/// * `socket_addr` - IP and Port for the remote DNS resolver
/// * `server_name` - The DNS name associated with a certificate
/// * `client_config` - Rustls client TLS configuration
/// * `provider` - Async runtime provider, for I/O and timers
#[allow(clippy::type_complexity)]
pub fn tls_client_connect_with_future<P, F>(
    future: F,
    socket_addr: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tls>, io::Error>>,
    BufDnsStreamHandle,
)
where
    P: RuntimeProvider,
    F: Future<Output = io::Result<P::Tcp>> + Send + Unpin + 'static,
{
    let (stream_future, sender) =
        tls_connect_with_future(future, socket_addr, server_name, client_config, provider);

    let new_future = Box::pin(async { Ok(TcpClientStream::from_stream(stream_future.await?)) });

    (new_future, sender)
}
