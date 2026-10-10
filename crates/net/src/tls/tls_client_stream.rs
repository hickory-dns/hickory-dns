// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::future::BoxFuture;
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;

use crate::{
    error::NetError,
    runtime::{
        DnsTcpStream, RuntimeProvider, Spawn,
        iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd},
    },
    tcp::{TcpClientStream, TcpStream},
    xfer::{BufDnsStreamHandle, CONNECT_TIMEOUT, DnsExchange, DnsMultiplexer, StreamReceiver},
};

/// Type of TlsClientStream used with Rustls
pub type TlsClientStream<S> = TcpClientStream<AsyncIoTokioAsStd<TlsStream<AsyncIoStdAsTokio<S>>>>;

/// Create a new [`DnsExchange`] wrapped around a multiplexed [`TlsClientStream`],
/// optionally binding the underlying TCP socket to a local address.
///
/// # Arguments
///
/// * `remote_addr` - Address of the remote nameserver
/// * `bind_addr` - Local address to bind the outgoing TCP socket to. When `None`, the OS picks.
/// * `server_name` - TLS server name for certificate validation
/// * `config` - TLS client configuration
/// * `timeout` - Timeout for requests
/// * `connect_timeout` - Timeout for the TCP connect step
/// * `max_active_requests` - Optional limit on concurrent in-flight requests.
///   If `None`, uses the default (32).
/// * `provider` - Runtime provider for spawning background tasks
#[allow(clippy::too_many_arguments)]
pub async fn tls_exchange<P: RuntimeProvider<Tcp = S>, S: DnsTcpStream>(
    remote_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    mut config: ClientConfig,
    timeout: Duration,
    connect_timeout: Duration,
    max_active_requests: Option<usize>,
    provider: P,
) -> Result<DnsExchange<P>, NetError> {
    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    config.enable_sni = false;

    let stream = provider
        .connect_tcp(remote_addr, bind_addr, Some(connect_timeout))
        .await?;
    let (future, sender) = tls_client_connect_with_future(
        stream,
        remote_addr,
        server_name.to_owned(),
        Arc::new(config),
    );

    let mut multiplexer = DnsMultiplexer::new(future.await?, sender).with_timeout(timeout);
    if let Some(max) = max_active_requests {
        multiplexer = multiplexer.with_max_active_requests(max);
    }
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

async fn connect_tls_stream<S: DnsTcpStream>(
    tls_connector: TlsConnector,
    stream: S,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    outbound_messages: StreamReceiver,
) -> Result<TcpStream<AsyncIoTokioAsStd<TlsStream<AsyncIoStdAsTokio<S>>>>, NetError> {
    let stream = AsyncIoStdAsTokio(stream);
    let s = match timeout(CONNECT_TIMEOUT, tls_connector.connect(server_name, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(NetError::from(e)),
        Err(_) => {
            debug!(%name_server, "TLS connect timeout");
            return Err(NetError::Timeout);
        }
    };

    Ok(TcpStream::from_stream_with_receiver(
        AsyncIoTokioAsStd(s),
        name_server,
        outbound_messages,
    ))
}
