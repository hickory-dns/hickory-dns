// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::marker::Unpin;
#[cfg(feature = "__quic")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
#[cfg(feature = "__https")]
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::proto::runtime::Spawn;
#[cfg(feature = "tokio")]
use crate::proto::runtime::TokioRuntimeProvider;
#[cfg(feature = "__tls")]
use crate::proto::runtime::iocompat::AsyncIoStdAsTokio;
use futures_util::future::FutureExt;
use futures_util::ready;
use futures_util::stream::{Stream, StreamExt};
#[cfg(feature = "__tls")]
use tokio_rustls::client::TlsStream as TokioTlsStream;

use crate::config::{NameServerConfig, ResolverOpts};
#[cfg(any(feature = "__h3", feature = "__https"))]
use crate::proto;
#[cfg(feature = "__https")]
use crate::proto::h2::{HttpsClientConnect, HttpsClientStream};
#[cfg(feature = "__h3")]
use crate::proto::h3::{H3ClientConnect, H3ClientStream};
#[cfg(feature = "__quic")]
use crate::proto::quic::{QuicClientConnect, QuicClientStream};
#[cfg(feature = "tokio")]
#[allow(unused_imports)] // Complicated cfg for which protocols are enabled
use crate::proto::runtime::TokioTime;
#[cfg(feature = "__tls")]
use crate::proto::runtime::iocompat::AsyncIoTokioAsStd;
use crate::proto::{
    ProtoError,
    runtime::RuntimeProvider,
    tcp::TcpClientStream,
    udp::{UdpClientConnect, UdpClientStream},
    xfer::{
        DnsExchange, DnsExchangeConnect, DnsExchangeSend, DnsHandle, DnsMultiplexer,
        DnsMultiplexerConnect, DnsRequest, DnsResponse, Protocol,
    },
};

/// Create `DnsHandle` with the help of `RuntimeProvider`.
/// This trait is designed for customization.
pub trait ConnectionProvider: 'static + Clone + Send + Sync + Unpin {
    /// The handle to the connection for sending DNS requests.
    type Conn: DnsHandle + Clone + Send + Sync + 'static;
    /// Ths future is responsible for spawning any background tasks as necessary.
    type FutureConn: Future<Output = Result<Self::Conn, ProtoError>> + Send + 'static;
    /// Provider that handles the underlying I/O and timing.
    type RuntimeProvider: RuntimeProvider;

    /// Create a new connection.
    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error>;
}

#[cfg(feature = "__tls")]
/// Predefined type for TLS client stream
type TlsClientStream<S> = TcpClientStream<AsyncIoTokioAsStd<TokioTlsStream<AsyncIoStdAsTokio<S>>>>;

/// The variants of all supported connections for the Resolver
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
pub(crate) enum ConnectionConnect<R: RuntimeProvider> {
    Udp(DnsExchangeConnect<UdpClientConnect<R>, UdpClientStream<R>, R::Timer>),
    Tcp(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                Pin<Box<dyn Future<Output = Result<TcpClientStream<R::Tcp>, ProtoError>> + Send>>,
                TcpClientStream<<R as RuntimeProvider>::Tcp>,
            >,
            DnsMultiplexer<TcpClientStream<<R as RuntimeProvider>::Tcp>>,
            R::Timer,
        >,
    ),
    #[cfg(feature = "__tls")]
    Tls(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                Pin<
                    Box<
                        dyn Future<
                                Output = Result<
                                    TlsClientStream<<R as RuntimeProvider>::Tcp>,
                                    ProtoError,
                                >,
                            > + Send
                            + 'static,
                    >,
                >,
                TlsClientStream<<R as RuntimeProvider>::Tcp>,
            >,
            DnsMultiplexer<TlsClientStream<<R as RuntimeProvider>::Tcp>>,
            TokioTime,
        >,
    ),
    #[cfg(all(feature = "__https", feature = "tokio"))]
    Https(DnsExchangeConnect<HttpsClientConnect<R::Tcp>, HttpsClientStream, TokioTime>),
    #[cfg(all(feature = "__quic", feature = "tokio"))]
    Quic(DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime>),
    #[cfg(all(feature = "__h3", feature = "tokio"))]
    H3(DnsExchangeConnect<H3ClientConnect, H3ClientStream, TokioTime>),
}

/// Resolves to a new Connection
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture<R: RuntimeProvider> {
    pub(crate) connect: ConnectionConnect<R>,
    pub(crate) spawner: R::Handle,
}

impl<R: RuntimeProvider> Future for ConnectionFuture<R> {
    type Output = Result<GenericConnection, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(match &mut self.connect {
            ConnectionConnect::Udp(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            ConnectionConnect::Tcp(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "__tls")]
            ConnectionConnect::Tls(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "__https")]
            ConnectionConnect::Https(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "__quic")]
            ConnectionConnect::Quic(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "__h3")]
            ConnectionConnect::H3(conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
        }))
    }
}

/// A connected DNS handle
#[derive(Clone)]
pub struct GenericConnection(DnsExchange);

impl DnsHandle for GenericConnection {
    type Response = ConnectionResponse;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        ConnectionResponse(self.0.send(request))
    }
}

/// Default ConnectionProvider with `GenericConnection`.
#[cfg(feature = "tokio")]
pub type TokioConnectionProvider = GenericConnector<TokioRuntimeProvider>;

/// Default connector for `GenericConnection`
#[derive(Clone)]
pub struct GenericConnector<P: RuntimeProvider> {
    runtime_provider: P,
}

impl<P: RuntimeProvider> GenericConnector<P> {
    /// Create a new instance.
    pub fn new(runtime_provider: P) -> Self {
        Self { runtime_provider }
    }
}

impl<P: RuntimeProvider + Default> Default for GenericConnector<P> {
    fn default() -> Self {
        Self {
            runtime_provider: P::default(),
        }
    }
}

impl<P: RuntimeProvider> ConnectionProvider for GenericConnector<P> {
    type Conn = GenericConnection;
    type FutureConn = ConnectionFuture<P>;
    type RuntimeProvider = P;

    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error> {
        let dns_connect = match (config.protocol, self.runtime_provider.quic_binder()) {
            (Protocol::Udp, _) => {
                let provider_handle = self.runtime_provider.clone();
                let stream = UdpClientStream::builder(config.socket_addr, provider_handle)
                    .with_timeout(Some(options.timeout))
                    .with_os_port_selection(options.os_port_selection)
                    .avoid_local_ports(options.avoid_local_udp_ports.clone())
                    .with_bind_addr(config.bind_addr)
                    .build();
                let exchange = DnsExchange::connect(stream);
                ConnectionConnect::Udp(exchange)
            }
            (Protocol::Tcp, _) => {
                let (future, handle) = TcpClientStream::new(
                    config.socket_addr,
                    config.bind_addr,
                    Some(options.timeout),
                    self.runtime_provider.clone(),
                );

                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(future, handle, options.timeout, None);
                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Tcp(exchange)
            }
            #[cfg(feature = "__tls")]
            (Protocol::Tls, _) => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                let tcp_future = self.runtime_provider.connect_tcp(socket_addr, None, None);

                let (stream, handle) = crate::tls::new_tls_stream_with_future(
                    tcp_future,
                    socket_addr,
                    tls_dns_name,
                    options.tls_config.clone(),
                );

                let dns_conn = DnsMultiplexer::with_timeout(stream, handle, timeout, None);
                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Tls(exchange)
            }
            #[cfg(feature = "__https")]
            (Protocol::Https, _) => {
                let socket_addr = config.socket_addr;
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                let http_endpoint = config
                    .http_endpoint
                    .clone()
                    .unwrap_or_else(|| proto::http::DEFAULT_DNS_QUERY_PATH.to_owned());
                let tcp_future = self.runtime_provider.connect_tcp(socket_addr, None, None);

                let exchange = crate::h2::new_https_stream_with_future(
                    tcp_future,
                    socket_addr,
                    tls_dns_name,
                    http_endpoint,
                    Arc::new(options.tls_config.clone()),
                );
                ConnectionConnect::Https(exchange)
            }
            #[cfg(feature = "__quic")]
            (Protocol::Quic, Some(binder)) => {
                let socket_addr = config.socket_addr;
                let bind_addr = config.bind_addr.unwrap_or(match socket_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                });
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                let client_config = options.tls_config.clone();
                let socket = binder.bind_quic(bind_addr, socket_addr)?;

                let exchange = crate::quic::new_quic_stream_with_future(
                    socket,
                    socket_addr,
                    tls_dns_name,
                    client_config,
                );
                ConnectionConnect::Quic(exchange)
            }
            #[cfg(feature = "__h3")]
            (Protocol::H3, Some(binder)) => {
                let socket_addr = config.socket_addr;
                let bind_addr = config.bind_addr.unwrap_or(match socket_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                });
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                let http_endpoint = config
                    .http_endpoint
                    .clone()
                    .unwrap_or_else(|| proto::http::DEFAULT_DNS_QUERY_PATH.to_owned());
                let client_config = options.tls_config.clone();
                let socket = binder.bind_quic(bind_addr, socket_addr)?;

                let exchange = crate::h3::new_h3_stream_with_future(
                    socket,
                    socket_addr,
                    tls_dns_name,
                    http_endpoint,
                    client_config,
                );
                ConnectionConnect::H3(exchange)
            }
            (protocol, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported protocol: {protocol:?}"),
                ));
            }
        };

        Ok(ConnectionFuture::<P> {
            connect: dns_connect,
            spawner: self.runtime_provider.create_handle(),
        })
    }
}

/// A stream of response to a DNS request.
#[must_use = "streams do nothing unless polled"]
pub struct ConnectionResponse(DnsExchangeSend);

impl Stream for ConnectionResponse {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(self.0.poll_next_unpin(cx)))
    }
}
