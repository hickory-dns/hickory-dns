// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::{Future, FutureExt};
use futures_util::ready;
use futures_util::stream::{Stream, StreamExt};
#[cfg(all(feature = "dns-over-native-tls", not(feature = "dns-over-rustls")))]
use tokio_native_tls::TlsStream as TokioTlsStream;
#[cfg(all(
    feature = "dns-over-openssl",
    not(feature = "dns-over-rustls"),
    not(feature = "dns-over-native-tls")
))]
use tokio_openssl::SslStream as TokioTlsStream;
#[cfg(feature = "dns-over-rustls")]
use tokio_rustls::client::TlsStream as TokioTlsStream;

#[cfg(feature = "dns-over-https")]
use proto::https::{HttpsClientConnect, HttpsClientStream};
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType};
use proto::{
    self,
    op::NoopMessageFinalizer,
    tcp::TcpClientConnect,
    tcp::TcpClientStream,
    udp::UdpClientConnect,
    udp::UdpClientStream,
    xfer::{
        DnsExchange, DnsExchangeConnect, DnsExchangeSend, DnsHandle, DnsMultiplexer,
        DnsMultiplexerConnect, DnsRequest, DnsResponse,
    },
    RuntimeProvider, Time,
};
#[cfg(feature = "dns-over-tls")]
use proto::{error::ProtoError, iocompat::AsyncIoTokioAsStd, TokioTime};

use crate::config::Protocol;
use crate::config::{NameServerConfig, ResolverOpts};
use crate::error::ResolveError;

/// A type to allow for custom ConnectionProviders. Needed mainly for mocking purposes.
///
/// ConnectionProvider is responsible for spawning any background tasks as necessary.
pub trait ConnectionProvider: 'static + Clone + Send + Sync + Unpin {
    /// The handle to the connect for sending DNS requests.
    type Conn: DnsHandle<Error = ResolveError> + Clone + Send + Sync + 'static;

    /// Ths future is responsible for spawning any background tasks as necessary
    type FutureConn: Future<Output = Result<Self::Conn, ResolveError>> + Send + 'static;

    /// The type used to set up timeout futures
    type Time: Time;

    /// The returned handle should
    fn new_connection(&self, config: &NameServerConfig, options: &ResolverOpts)
        -> Self::FutureConn;
}

/// A type defines the Handle which can spawn future.
pub trait Spawn {}

/// Standard connection implements the default mechanism for creating new Connections
#[derive(Clone)]
pub struct GenericConnectionProvider<R: RuntimeProvider>(R);

impl<R: RuntimeProvider> GenericConnectionProvider<R> {
    pub fn new(runtime: R) -> Self {
        Self(runtime)
    }
}

impl<R> ConnectionProvider for GenericConnectionProvider<R>
where
    R: RuntimeProvider,
{
    type Conn = GenericConnection;
    type FutureConn = ConnectionFuture<R>;
    type Time = R::Time;

    /// Constructs an initial constructor for the ConnectionHandle to be used to establish a
    ///   future connection.
    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Self::FutureConn {
        let dns_connect = match config.protocol {
            Protocol::Udp => {
                let stream = UdpClientStream::<R>::with_timeout(
                    config.socket_addr,
                    options.timeout,
                    self.0.clone(),
                );
                let exchange = DnsExchange::connect(stream);
                ConnectionConnect::Udp(exchange)
            }
            Protocol::Tcp => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;

                let (stream, handle) = TcpClientStream::<R::TcpConnection>::with_timeout(
                    socket_addr,
                    timeout,
                    self.0.clone(),
                );
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Tcp(exchange)
            }
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                #[cfg(feature = "dns-over-rustls")]
                let client_config = config.tls_config.clone();

                #[cfg(feature = "dns-over-rustls")]
                let (stream, handle) = {
                    crate::tls::new_tls_stream::<R>(
                        socket_addr,
                        tls_dns_name,
                        client_config,
                        self.0.clone(),
                    )
                };
                #[cfg(not(feature = "dns-over-rustls"))]
                let (stream, handle) =
                    { crate::tls::new_tls_stream::<R>(socket_addr, tls_dns_name, self.0.clone()) };

                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Tls(exchange)
            }
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => {
                let socket_addr = config.socket_addr;
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                #[cfg(feature = "dns-over-rustls")]
                let client_config = config.tls_config.clone();

                let exchange = crate::https::new_https_stream::<R>(
                    socket_addr,
                    tls_dns_name,
                    client_config,
                    self.0.clone(),
                );
                ConnectionConnect::Https(exchange)
            }
            #[cfg(feature = "mdns")]
            Protocol::Mdns => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;

                let (stream, handle) =
                    MdnsClientStream::new(socket_addr, MdnsQueryType::OneShot, None, None, None);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let exchange = DnsExchange::connect(dns_conn);
                ConnectionConnect::Mdns(exchange)
            }
        };

        ConnectionFuture {
            connect: dns_connect,
            spawner: self.0.clone(),
        }
    }
}

#[cfg(feature = "dns-over-tls")]
/// Predefined type for TLS client stream
type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<TokioTlsStream<proto::iocompat::AsyncIoStdAsTokio<S>>>>;

/// The variants of all supported connections for the Resolver
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
pub(crate) enum ConnectionConnect<R: RuntimeProvider> {
    Udp(DnsExchangeConnect<UdpClientConnect<R>, UdpClientStream<R>, R::Time>),
    Tcp(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                TcpClientConnect<R::TcpConnection>,
                TcpClientStream<R::TcpConnection>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TcpClientStream<R::TcpConnection>, NoopMessageFinalizer>,
            R::Time,
        >,
    ),
    #[cfg(feature = "dns-over-tls")]
    Tls(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                Pin<
                    Box<
                        dyn Future<Output = Result<TlsClientStream<R::TcpConnection>, ProtoError>>
                            + Send
                            + 'static,
                    >,
                >,
                TlsClientStream<R::TcpConnection>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TlsClientStream<R::TcpConnection>, NoopMessageFinalizer>,
            TokioTime,
        >,
    ),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeConnect<HttpsClientConnect<R>, HttpsClientStream, TokioTime>),
    #[cfg(feature = "mdns")]
    Mdns(
        DnsExchangeConnect<
            DnsMultiplexerConnect<MdnsClientConnect, MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexer<MdnsClientStream, NoopMessageFinalizer>,
            TokioTime,
        >,
    ),
}

/// Resolves to a new Connection
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture<R: RuntimeProvider> {
    connect: ConnectionConnect<R>,
    spawner: R,
}

impl<R: RuntimeProvider> Future for ConnectionFuture<R> {
    type Output = Result<GenericConnection, ResolveError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(match &mut self.connect {
            ConnectionConnect::Udp(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            ConnectionConnect::Tcp(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "dns-over-tls")]
            ConnectionConnect::Tls(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionConnect::Https(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                self.spawner.spawn_bg(bg);
                GenericConnection(conn)
            }
            #[cfg(feature = "mdns")]
            ConnectionConnect::Mdns(ref mut conn) => {
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
    type Error = ResolveError;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        ConnectionResponse(self.0.send(request))
    }
}

/// A stream of response to a DNS request.
#[must_use = "steam do nothing unless polled"]
pub struct ConnectionResponse(DnsExchangeSend);

impl Stream for ConnectionResponse {
    type Item = Result<DnsResponse, ResolveError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(ready!(self.0.poll_next_unpin(cx)).map(|r| r.map_err(ResolveError::from)))
    }
}

#[cfg(feature = "tokio-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-runtime")))]
#[allow(unreachable_pub)]
pub mod tokio_runtime {
    pub type TokioConnection = super::GenericConnection;
    pub type TokioConnectionProvider = super::GenericConnectionProvider<crate::proto::TokioRuntime>;
}
