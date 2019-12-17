// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Future, FutureExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::{self, runtime::Handle};
#[cfg(all(
    feature = "dns-over-openssl",
    not(feature = "dns-over-rustls"),
    not(feature = "dns-over-native-tls")
))]
use tokio_openssl::SslStream as TokioTlsStream;
#[cfg(feature = "dns-over-rustls")]
use tokio_rustls::client::TlsStream as TokioTlsStream;
#[cfg(all(feature = "dns-over-native-tls", not(feature = "dns-over-rustls")))]
use tokio_tls::TlsStream as TokioTlsStream;

use proto;
use proto::error::ProtoError;
use proto::iocompat::Compat02As03;
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientConnect, MdnsClientStream, MdnsQueryType};
use proto::op::NoopMessageFinalizer;
use proto::tcp::{TcpClientConnect, TcpClientStream};
use proto::udp::{UdpClientConnect, UdpClientStream, UdpResponse};
use proto::xfer::{
    DnsExchange, DnsExchangeBackground, DnsExchangeConnect, DnsExchangeSend, DnsHandle,
    DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse, DnsRequest, DnsResponse,
};
use proto::TokioTime;

#[cfg(feature = "dns-over-https")]
use trust_dns_https::{self, HttpsClientConnect, HttpsClientResponse, HttpsClientStream};

use crate::config::{NameServerConfig, Protocol, ResolverOpts};

/// A type to allow for custom ConnectionProviders. Needed mainly for mocking purposes.
///
/// ConnectionProvider is responsible for spawning any background tasks as necessary.
pub trait ConnectionProvider: 'static + Clone + Send + Sync + Unpin {
    /// The handle to the connect for sending DNS requests.
    type Conn: DnsHandle + Clone + Send + Sync + 'static;

    /// Ths future is responsible for spawning any background tasks as necessary
    type FutureConn: Future<Output = Result<Self::Conn, ProtoError>> + Send + 'static;

    /// The returned handle should
    fn new_connection(&self, config: &NameServerConfig, options: &ResolverOpts)
        -> Self::FutureConn;
}

fn spawn_bg<F: Future<Output = Result<(), ProtoError>> + Send + 'static>(
    spawner: &Handle,
    background: F,
) {
    // TODO: maybe do something with this in the future?
    let _join = spawner.spawn(background);
}

/// Standard connection implements the default mechanism for creating new Connections
#[derive(Clone)]
pub struct TokioConnectionProvider(Handle);

impl TokioConnectionProvider {
    pub(crate) fn new(runtime: Handle) -> Self {
        Self(runtime)
    }
}

impl ConnectionProvider for TokioConnectionProvider {
    type Conn = TokioConnection;
    type FutureConn = TokioConnectionFuture;

    /// Constructs an initial constructor for the ConnectionHandle to be used to establish a
    ///   future connection.
    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Self::FutureConn {
        let dns_connect = match config.protocol {
            Protocol::Udp => {
                let stream = UdpClientStream::<TokioUdpSocket>::with_timeout(
                    config.socket_addr,
                    options.timeout,
                );
                let exchange = DnsExchange::connect(stream);
                ConnectionConnect::Udp(exchange)
            }
            Protocol::Tcp => {
                let socket_addr = config.socket_addr;
                let timeout = options.timeout;

                let (stream, handle) =
                    TcpClientStream::<Compat02As03<TokioTcpStream>>::with_timeout::<TokioTime>(
                        socket_addr,
                        timeout,
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
                let (stream, handle) =
                    { crate::tls::new_tls_stream(socket_addr, tls_dns_name, client_config) };
                #[cfg(not(feature = "dns-over-rustls"))]
                let (stream, handle) = { crate::tls::new_tls_stream(socket_addr, tls_dns_name) };

                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    Box::new(handle),
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

                let exchange =
                    crate::https::new_https_stream(socket_addr, tls_dns_name, client_config);
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

        TokioConnectionFuture {
            connect: dns_connect,
            spawner: self.0.clone(),
        }
    }
}

/// The variants of all supported connections for the Resolver
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
pub(crate) enum ConnectionConnect {
    Udp(
        DnsExchangeConnect<
            UdpClientConnect<TokioUdpSocket>,
            UdpClientStream<TokioUdpSocket>,
            UdpResponse,
            TokioTime,
        >,
    ),
    Tcp(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                TcpClientConnect<Compat02As03<TokioTcpStream>>,
                TcpClientStream<Compat02As03<TokioTcpStream>>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<TcpClientStream<Compat02As03<TokioTcpStream>>, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
            TokioTime,
        >,
    ),
    #[cfg(feature = "dns-over-tls")]
    Tls(
        DnsExchangeConnect<
            DnsMultiplexerConnect<
                Pin<
                    Box<
                        dyn futures::Future<
                                Output = Result<
                                    TcpClientStream<TokioTlsStream<Compat02As03<TokioTcpStream>>>,
                                    ProtoError,
                                >,
                            > + Send
                            + 'static,
                    >,
                >,
                TcpClientStream<TokioTlsStream<Compat02As03<TokioTcpStream>>>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexer<
                TcpClientStream<TokioTlsStream<Compat02As03<TokioTcpStream>>>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexerSerialResponse,
            TokioTime,
        >,
    ),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeConnect<HttpsClientConnect, HttpsClientStream, HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(
        DnsExchangeConnect<
            DnsMultiplexerConnect<MdnsClientConnect, MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexer<MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
            TokioTime,
        >,
    ),
}

/// Resolves to a new Connection
#[must_use = "futures do nothing unless polled"]
pub struct TokioConnectionFuture {
    connect: ConnectionConnect,
    spawner: Handle,
}

impl Future for TokioConnectionFuture {
    type Output = Result<TokioConnection, ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let (connection, bg) = match &mut self.connect {
            ConnectionConnect::Udp(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = TokioConnection(ConnectionConnected::Udp(conn));
                let bg = ConnectionBackground(ConnectionBackgroundInner::Udp(bg));
                (conn, bg)
            }
            ConnectionConnect::Tcp(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = TokioConnection(ConnectionConnected::Tcp(conn));
                let bg = ConnectionBackground(ConnectionBackgroundInner::Tcp(bg));
                (conn, bg)
            }
            #[cfg(feature = "dns-over-tls")]
            ConnectionConnect::Tls(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = TokioConnection(ConnectionConnected::Tls(conn));
                let bg = ConnectionBackground(ConnectionBackgroundInner::Tls(bg));
                (conn, bg)
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionConnect::Https(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = TokioConnection(ConnectionConnected::Https(conn));
                let bg = ConnectionBackground(ConnectionBackgroundInner::Https(bg));
                (conn, bg)
            }
            #[cfg(feature = "mdns")]
            ConnectionConnect::Mdns(ref mut conn) => {
                let (conn, bg) = ready!(conn.poll_unpin(cx))?;
                let conn = TokioConnection(ConnectionConnected::Mdns(conn));
                let bg = ConnectionBackground(ConnectionBackgroundInner::Mdns(bg));
                (conn, bg)
            }
        };

        spawn_bg(&self.spawner, bg);
        Poll::Ready(Ok(connection))
    }
}

/// A connected DNS handle
#[derive(Clone)]
pub struct TokioConnection(ConnectionConnected);

impl DnsHandle for TokioConnection {
    type Response = ConnectionResponse;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        self.0.send(request)
    }
}

/// A representation of an established connection
#[derive(Clone)]
enum ConnectionConnected {
    Udp(DnsExchange<UdpResponse>),
    Tcp(DnsExchange<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-tls")]
    Tls(DnsExchange<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchange<HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(DnsExchange<DnsMultiplexerSerialResponse>),
}

impl DnsHandle for ConnectionConnected {
    type Response = ConnectionResponse;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&mut self, request: R) -> Self::Response {
        let response = match self {
            ConnectionConnected::Udp(ref mut conn) => {
                ConnectionResponseInner::Udp(conn.send(request))
            }
            ConnectionConnected::Tcp(ref mut conn) => {
                ConnectionResponseInner::Tcp(conn.send(request))
            }
            #[cfg(feature = "dns-over-tls")]
            ConnectionConnected::Tls(ref mut conn) => {
                ConnectionResponseInner::Tls(conn.send(request))
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionConnected::Https(ref mut https) => {
                ConnectionResponseInner::Https(https.send(request))
            }
            #[cfg(feature = "mdns")]
            ConnectionConnected::Mdns(ref mut mdns) => {
                ConnectionResponseInner::Mdns(mdns.send(request))
            }
        };

        ConnectionResponse(response)
    }
}

/// A wrapper type to switch over a connection that still needs to be made, or is already established
#[must_use = "futures do nothing unless polled"]
enum ConnectionResponseInner {
    Udp(DnsExchangeSend<UdpResponse>),
    Tcp(DnsExchangeSend<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-tls")]
    Tls(DnsExchangeSend<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeSend<HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(DnsExchangeSend<DnsMultiplexerSerialResponse>),
}

impl Future for ConnectionResponseInner {
    type Output = Result<DnsResponse, proto::error::ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        use self::ConnectionResponseInner::*;

        trace!("polling response inner");
        match *self {
            Udp(ref mut resp) => resp.poll_unpin(cx),
            Tcp(ref mut resp) => resp.poll_unpin(cx),
            #[cfg(feature = "dns-over-tls")]
            Tls(ref mut tls) => tls.poll_unpin(cx),
            #[cfg(feature = "dns-over-https")]
            Https(ref mut https) => https.poll_unpin(cx),
            #[cfg(feature = "mdns")]
            Mdns(ref mut mdns) => mdns.poll_unpin(cx),
        }
    }
}

/// A future response from a DNS request.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionResponse(ConnectionResponseInner);

impl Future for ConnectionResponse {
    type Output = Result<DnsResponse, proto::error::ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

/// A background task for driving the DNS protocol of the connection
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionBackground(ConnectionBackgroundInner);

impl Future for ConnectionBackground {
    type Output = Result<(), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

#[allow(clippy::large_enum_variant)]
#[allow(clippy::type_complexity)]
#[must_use = "futures do nothing unless polled"]
pub(crate) enum ConnectionBackgroundInner {
    Udp(DnsExchangeBackground<UdpClientStream<TokioUdpSocket>, UdpResponse, TokioTime>),
    Tcp(
        DnsExchangeBackground<
            DnsMultiplexer<TcpClientStream<Compat02As03<TokioTcpStream>>, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
            TokioTime,
        >,
    ),
    #[cfg(feature = "dns-over-tls")]
    Tls(
        DnsExchangeBackground<
            DnsMultiplexer<
                TcpClientStream<TokioTlsStream<Compat02As03<TokioTcpStream>>>,
                NoopMessageFinalizer,
            >,
            DnsMultiplexerSerialResponse,
            TokioTime,
        >,
    ),
    #[cfg(feature = "dns-over-https")]
    Https(DnsExchangeBackground<HttpsClientStream, HttpsClientResponse>),
    #[cfg(feature = "mdns")]
    Mdns(
        DnsExchangeBackground<
            DnsMultiplexer<MdnsClientStream, NoopMessageFinalizer>,
            DnsMultiplexerSerialResponse,
            TokioTime,
        >,
    ),
}

impl Future for ConnectionBackgroundInner {
    type Output = Result<(), ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        use self::ConnectionBackgroundInner::*;

        trace!("polling response inner");
        match *self {
            Udp(ref mut bg) => bg.poll_unpin(cx),
            Tcp(ref mut bg) => bg.poll_unpin(cx),
            #[cfg(feature = "dns-over-tls")]
            Tls(ref mut bg) => bg.poll_unpin(cx),
            #[cfg(feature = "dns-over-https")]
            Https(ref mut bg) => bg.poll_unpin(cx),
            #[cfg(feature = "mdns")]
            Mdns(ref mut bg) => bg.poll_unpin(cx),
        }
    }
}
