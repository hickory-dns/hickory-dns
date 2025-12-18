// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS over TLS client implementation for Rustls

use core::future::Future;
use core::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use rustls::{ClientConfig, pki_types::ServerName};
use tokio_rustls::TlsConnector;

use super::tls_stream::connect_tls_stream;
use crate::error::NetError;
use crate::runtime::iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd};
use crate::runtime::{DnsTcpStream, RuntimeProvider, Spawn};
use crate::tcp::TcpClientStream;
use crate::xfer::{BufDnsStreamHandle, DnsExchange, DnsMultiplexer};

/// Type of TlsClientStream used with Rustls
pub type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>>>;

/// Create a new [`DnsExchange`] wrapped around a multiplexed [`TlsClientStream`]
pub async fn tls_exchange<P: RuntimeProvider<Tcp = S>, S: DnsTcpStream>(
    remote_addr: SocketAddr,
    server_name: ServerName<'static>,
    mut config: ClientConfig,
    timeout: Duration,
    provider: P,
) -> Result<DnsExchange<P>, NetError> {
    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    config.enable_sni = false;

    let stream = provider.connect_tcp(remote_addr, None, None).await?;
    let (future, sender) = tls_client_connect_with_future(
        stream,
        remote_addr,
        server_name.to_owned(),
        Arc::new(config),
    );

    let multiplexer = DnsMultiplexer::with_timeout(future.await?, sender, timeout, None);
    let (exchange, bg) = DnsExchange::<P>::from_stream(multiplexer);
    provider.create_handle().spawn_bg(bg);
    Ok(exchange)
}

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
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tcp>, NetError>>,
    BufDnsStreamHandle,
) {
    tls_client_connect_with_bind_addr(name_server, None, server_name, client_config, provider)
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
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    provider: P,
) -> (
    BoxFuture<'static, Result<TlsClientStream<P::Tcp>, NetError>>,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);
    let early_data_enabled = client_config.enable_early_data;
    let tls_connector = TlsConnector::from(client_config).early_data(early_data_enabled);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = async move {
        let tcp = provider.connect_tcp(name_server, bind_addr, None).await?;
        connect_tls_stream(
            tls_connector,
            tcp,
            name_server,
            server_name,
            outbound_messages,
        )
        .await
    };

    let new_future = Box::pin(async { Ok(TcpClientStream::from_stream(stream.await?)) });

    (new_future, message_sender)
}

/// Creates a new TlsStream to the specified name_server connecting from a specific address.
///
/// # Arguments
///
/// * `future` - A future producing DnsTcpStream
/// * `dns_name` - The DNS name associated with a certificate
fn tls_client_connect_with_future<S: DnsTcpStream>(
    stream: S,
    socket_addr: SocketAddr,
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
) -> (
    impl Future<Output = Result<TlsClientStream<S>, NetError>> + Send + 'static,
    BufDnsStreamHandle,
) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(socket_addr);
    let early_data_enabled = client_config.enable_early_data;
    let tls_connector = TlsConnector::from(client_config).early_data(early_data_enabled);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = async move {
        connect_tls_stream(
            tls_connector,
            stream,
            socket_addr,
            server_name,
            outbound_messages,
        )
        .await
    };

    (
        async move { Ok(TcpClientStream::from_stream(stream.await?)) },
        message_sender,
    )
}
