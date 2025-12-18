// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over TLS

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::future::BoxFuture;
#[cfg(not(feature = "rustls-platform-verifier"))]
use rustls::RootCertStore;
use rustls::{
    ClientConfig,
    crypto::{self, CryptoProvider},
    pki_types::ServerName,
};
#[cfg(feature = "rustls-platform-verifier")]
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
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

pub(super) async fn connect_tls_stream<S: DnsTcpStream>(
    tls_connector: TlsConnector,
    stream: S,
    name_server: SocketAddr,
    server_name: ServerName<'static>,
    outbound_messages: StreamReceiver,
) -> Result<TcpStream<AsyncIoTokioAsStd<TokioTlsClientStream<S>>>, NetError> {
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

/// Initializes a TlsStream with an existing tokio_tls::TlsStream.
///
/// This is intended for use with a TlsListener and Incoming connections
pub fn tls_from_stream<S: DnsTcpStream>(
    stream: S,
    peer_addr: SocketAddr,
) -> (TlsStream<S>, BufDnsStreamHandle) {
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(peer_addr);
    let stream = TcpStream::from_stream_with_receiver(stream, peer_addr, outbound_messages);
    (stream, message_sender)
}

/// Make a new [`ClientConfig`] with the default settings
pub fn client_config() -> Result<ClientConfig, rustls::Error> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap();

    #[cfg(feature = "rustls-platform-verifier")]
    let builder = builder.with_platform_verifier()?;
    #[cfg(not(feature = "rustls-platform-verifier"))]
    let builder = builder.with_root_certificates({
        #[cfg_attr(not(feature = "webpki-roots"), allow(unused_mut))]
        let mut root_store = RootCertStore::empty();
        #[cfg(feature = "webpki-roots")]
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    });

    Ok(builder.with_no_client_auth())
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub fn default_provider() -> CryptoProvider {
    crypto::aws_lc_rs::default_provider()
}

/// Instantiate a new [`CryptoProvider`] for use with rustls
#[cfg(feature = "tls-ring")]
pub fn default_provider() -> CryptoProvider {
    crypto::ring::default_provider()
}

/// Predefined type for abstracting the base I/O TlsStream with TokioTls
pub type TlsStream<S> = TcpStream<S>;

/// Predefined type for abstracting the TlsClientStream with TokioTls
pub type TokioTlsClientStream<S> = tokio_rustls::client::TlsStream<AsyncIoStdAsTokio<S>>;
