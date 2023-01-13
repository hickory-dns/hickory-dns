// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::marker::Unpin;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::{Future, FutureExt};
use futures_util::stream::{Stream, StreamExt};
use futures_util::{ready, AsyncRead, AsyncWrite};
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

#[cfg(feature = "dns-over-https")]
use proto::https::{HttpsClientConnect, HttpsClientStream};
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType};
#[cfg(feature = "dns-over-quic")]
use proto::quic::{QuicClientConnect, QuicClientStream, QuicLocalAddr};
use proto::tcp::DnsTcpStream;
use proto::udp::DnsUdpSocket;
use proto::{
    self,
    error::ProtoError,
    op::NoopMessageFinalizer,
    tcp::Connect,
    tcp::TcpClientConnect,
    tcp::TcpClientStream,
    udp::UdpClientConnect,
    udp::{UdpClientStream, UdpSocket},
    xfer::{
        DnsExchange, DnsExchangeConnect, DnsExchangeSend, DnsHandle, DnsMultiplexer,
        DnsMultiplexerConnect, DnsRequest, DnsResponse,
    },
    Time,
};
#[cfg(feature = "tokio-runtime")]
use proto::{iocompat::AsyncIoTokioAsStd, TokioTime};

use crate::config::Protocol;
use crate::config::{NameServerConfig, ResolverOpts};
use crate::error::ResolveError;

/// RuntimeProvider defines which async runtime that handles IO and timers.
pub trait RuntimeProvider: Clone + 'static {
    /// Handle to the executor;
    type Handle: Clone + Send + Spawn + Sync + Unpin;

    /// Timer
    type Timer: Time + Send + Unpin;

    #[cfg(not(feature = "dns-over-quic"))]
    /// UdpSocket
    type Udp: DnsUdpSocket + Send;
    #[cfg(feature = "dns-over-quic")]
    /// UdpSocket
    type Udp: DnsUdpSocket + QuicLocalAddr + Send;

    /// TcpStream
    type Tcp: DnsTcpStream;

    /// Create a TCP connection with custom configuration.
    fn connect_tcp(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> ConnectionFuture<Self::Tcp>;

    /// Create a UDP socket with custom configuration.
    /// *Notice: the future should be ready once returned at best effort. Otherwise UDP DNS may need much more retries.*
    fn bind_udp(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> ConnectionFuture<Self::Udp>;
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
    #[cfg(feature = "dns-over-tls")]
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
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeConnect<HttpsClientConnect<R::Tcp>, HttpsClientStream, TokioTime>),
    #[cfg(feature = "dns-over-quic")]
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
            self.join_set.lock().unwrap().spawn(future);
        }
    }

    /// The Tokio Runtime for async execution
    #[derive(Clone, Copy)]
    pub struct TokioRuntime;

    impl RuntimeProvider for TokioRuntime {
        type Handle = TokioHandle;
        type Tcp = AsyncIoTokioAsStd<TokioTcpStream>;
        type Timer = TokioTime;
        type Udp = TokioUdpSocket;
    }

    /// An alias for Tokio use cases
    pub type TokioConnection = GenericConnection;

    /// An alias for Tokio use cases
    pub type TokioConnectionProvider = GenericConnectionProvider<TokioRuntime>;
}
