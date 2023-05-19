// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io;
use std::marker::Unpin;
use std::net::SocketAddr;
#[cfg(feature = "dns-over-quic")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::{Future, FutureExt};
use futures_util::ready;
use futures_util::stream::{Stream, StreamExt};
#[cfg(feature = "tokio-runtime")]
use tokio::net::TcpStream as TokioTcpStream;
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

use crate::config::{NameServerConfig, Protocol, ResolverOpts};
#[cfg(feature = "dns-over-https")]
use proto::https::{HttpsClientConnect, HttpsClientStream};
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType};
#[cfg(feature = "dns-over-quic")]
use proto::quic::{QuicClientConnect, QuicClientStream};
use proto::tcp::DnsTcpStream;
use proto::udp::DnsUdpSocket;
use proto::{
    self,
    error::ProtoError,
    op::NoopMessageFinalizer,
    tcp::TcpClientConnect,
    tcp::TcpClientStream,
    udp::UdpClientConnect,
    udp::UdpClientStream,
    xfer::{
        DnsExchange, DnsExchangeConnect, DnsExchangeSend, DnsHandle, DnsMultiplexer,
        DnsMultiplexerConnect, DnsRequest, DnsResponse,
    },
    Time,
};
#[cfg(feature = "tokio-runtime")]
use proto::{iocompat::AsyncIoTokioAsStd, TokioTime};
#[cfg(feature = "dns-over-quic")]
use trust_dns_proto::udp::QuicLocalAddr;

use crate::error::ResolveError;

/// RuntimeProvider defines which async runtime that handles IO and timers.
pub trait RuntimeProvider: Clone + Send + Sync + Unpin + 'static {
    /// Handle to the executor;
    type Handle: Clone + Send + Spawn + Sync + Unpin;

    /// Timer
    type Timer: Time + Send + Unpin;

    #[cfg(not(feature = "dns-over-quic"))]
    /// UdpSocket
    type Udp: DnsUdpSocket + Send;
    #[cfg(feature = "dns-over-quic")]
    /// UdpSocket, where `QuicLocalAddr` is for `quinn` crate.
    type Udp: DnsUdpSocket + QuicLocalAddr + Send;

    /// TcpStream
    type Tcp: DnsTcpStream;

    /// Create a runtime handle
    fn create_handle(&self) -> Self::Handle;

    /// Create a TCP connection with custom configuration.
    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>>;

    /// Create a UDP socket bound to `local_addr`. The returned value should **not** be connected to `server_addr`.
    /// *Notice: the future should be ready once returned at best effort. Otherwise UDP DNS may need much more retries.*
    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>>;
}

/// Create `DnsHandle` with the help of `RuntimeProvider`.
/// This trait is designed for customization.
pub trait ConnectionProvider: 'static + Clone + Send + Sync + Unpin {
    /// The handle to the connect for sending DNS requests.
    type Conn: DnsHandle<Error = ResolveError> + Clone + Send + Sync + 'static;
    /// Ths future is responsible for spawning any background tasks as necessary.
    type FutureConn: Future<Output = Result<Self::Conn, ResolveError>> + Send + 'static;
    /// Provider that handles the underlying I/O and timing.
    type RuntimeProvider: RuntimeProvider;

    /// Create a new connection.
    fn new_connection(&self, config: &NameServerConfig, options: &ResolverOpts)
        -> Self::FutureConn;
}

/// A type defines the Handle which can spawn future.
pub trait Spawn {
    /// Spawn a future in the background
    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static;
}

#[cfg(feature = "dns-over-tls")]
/// Predefined type for TLS client stream
type TlsClientStream<S> =
    TcpClientStream<AsyncIoTokioAsStd<TokioTlsStream<proto::iocompat::AsyncIoStdAsTokio<S>>>>;

/// The variants of all supported connections for the Resolver
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
pub(crate) enum ConnectionConnect<R: RuntimeProvider> {
    Udp(DnsExchangeConnect<UdpClientConnect<R::Udp>, UdpClientStream<R::Udp>, R::Timer>),
    Tcp(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                TcpClientConnect<<R as RuntimeProvider>::Tcp>,
                TcpClientStream<<R as RuntimeProvider>::Tcp>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TcpClientStream<<R as RuntimeProvider>::Tcp>, NoopMessageFinalizer>,
            R::Timer,
        >,
    ),
    #[cfg(all(feature = "dns-over-tls", feature = "tokio-runtime"))]
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
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TlsClientStream<<R as RuntimeProvider>::Tcp>, NoopMessageFinalizer>,
            TokioTime,
        >,
    ),
    #[cfg(all(feature = "dns-over-https", feature = "tokio-runtime"))]
    Https(DnsExchangeConnect<HttpsClientConnect<R::Tcp>, HttpsClientStream, TokioTime>),
    #[cfg(all(feature = "dns-over-quic", feature = "tokio-runtime"))]
    Quic(DnsExchangeConnect<QuicClientConnect, QuicClientStream, TokioTime>),
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
    pub(crate) connect: ConnectionConnect<R>,
    pub(crate) spawner: R::Handle,
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
            #[cfg(feature = "dns-over-quic")]
            ConnectionConnect::Quic(ref mut conn) => {
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
    ) -> Self::FutureConn {
        let dns_connect = match config.protocol {
            Protocol::Udp => {
                let provider_handle = self.runtime_provider.clone();
                let closure = move |local_addr: SocketAddr, server_addr: SocketAddr| {
                    provider_handle.bind_udp(local_addr, server_addr)
                };
                let stream = UdpClientStream::with_creator(
                    config.socket_addr,
                    None,
                    options.timeout,
                    Arc::new(closure),
                );
                let exchange = DnsExchange::connect(stream);
                ConnectionConnect::Udp(exchange)
            }
            Protocol::Tcp => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;
                let tcp_future = self.runtime_provider.connect_tcp(socket_addr);

                let (stream, handle) =
                    TcpClientStream::with_future(tcp_future, socket_addr, timeout);
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
                let tcp_future = self.runtime_provider.connect_tcp(socket_addr);

                #[cfg(feature = "dns-over-rustls")]
                let client_config = config.tls_config.clone();

                #[cfg(feature = "dns-over-rustls")]
                let (stream, handle) = {
                    crate::tls::new_tls_stream_with_future(
                        tcp_future,
                        socket_addr,
                        tls_dns_name,
                        client_config,
                    )
                };
                #[cfg(not(feature = "dns-over-rustls"))]
                let (stream, handle) = {
                    crate::tls::new_tls_stream_with_future(tcp_future, socket_addr, tls_dns_name)
                };

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
                let tcp_future = self.runtime_provider.connect_tcp(socket_addr);

                let exchange = crate::https::new_https_stream_with_future(
                    tcp_future,
                    socket_addr,
                    tls_dns_name,
                    client_config,
                );
                ConnectionConnect::Https(exchange)
            }
            #[cfg(feature = "dns-over-quic")]
            Protocol::Quic => {
                let socket_addr = config.socket_addr;
                let bind_addr = config.bind_addr.unwrap_or(match socket_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                    SocketAddr::V6(_) => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0)
                    }
                });
                let tls_dns_name = config.tls_dns_name.clone().unwrap_or_default();
                #[cfg(feature = "dns-over-rustls")]
                let client_config = config.tls_config.clone();
                let udp_future = self.runtime_provider.bind_udp(bind_addr, socket_addr);

                let exchange = crate::quic::new_quic_stream_with_future(
                    udp_future,
                    socket_addr,
                    tls_dns_name,
                    client_config,
                );
                ConnectionConnect::Quic(exchange)
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

        ConnectionFuture::<P> {
            connect: dns_connect,
            spawner: self.runtime_provider.create_handle(),
        }
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
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket as TokioUdpSocket;
    use tokio::task::JoinSet;

    /// A handle to the Tokio runtime
    #[derive(Clone, Default)]
    pub struct TokioHandle {
        join_set: Arc<Mutex<JoinSet<Result<(), ProtoError>>>>,
    }

    impl Spawn for TokioHandle {
        fn spawn_bg<F>(&mut self, future: F)
        where
            F: Future<Output = Result<(), ProtoError>> + Send + 'static,
        {
            let mut join_set = self.join_set.lock().unwrap();
            join_set.spawn(future);
            reap_tasks(&mut join_set);
        }
    }

    /// The Tokio Runtime for async execution
    #[derive(Clone, Default)]
    pub struct TokioRuntimeProvider(TokioHandle);

    impl TokioRuntimeProvider {
        /// Create a Tokio runtime
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl RuntimeProvider for TokioRuntimeProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = TokioUdpSocket;
        type Tcp = AsyncIoTokioAsStd<TokioTcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.0.clone()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
            Box::pin(async move {
                TokioTcpStream::connect(server_addr)
                    .await
                    .map(AsyncIoTokioAsStd)
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
            Box::pin(tokio::net::UdpSocket::bind(local_addr))
        }
    }

    /// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
    fn reap_tasks(join_set: &mut JoinSet<Result<(), ProtoError>>) {
        while FutureExt::now_or_never(join_set.join_next()).is_some() {}
    }

    /// Default ConnectionProvider with `GenericConnection`.
    pub type TokioConnectionProvider = GenericConnector<TokioRuntimeProvider>;
}
