// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{Future, FutureExt,  TryFutureExt};
use tokio;

use proto;
#[cfg(feature = "mdns")]
use proto::multicast::{MdnsClientStream, MdnsQueryType};
use proto::op::NoopMessageFinalizer;
use proto::tcp::TcpClientStream;
use proto::udp::{UdpClientStream, UdpResponse};
use proto::xfer::{
    self, BufDnsRequestStreamHandle, DnsExchange, DnsHandle, DnsMultiplexer,
    DnsMultiplexerSerialResponse, DnsRequest, DnsResponse,
};
#[cfg(feature = "dns-over-https")]
use trust_dns_https::{self, HttpsClientResponse};

#[cfg(feature = "dns-over-rustls")]
use crate::config::TlsClientConfig;
use crate::config::{NameServerConfig, Protocol, ResolverOpts};

/// A type to allow for custom ConnectionProviders. Needed mainly for mocking purposes.
pub trait ConnectionProvider: 'static  + Clone + Send + Sync + Unpin {
    type ConnHandle;

    /// The returned handle should
    fn new_connection(&self, config: &NameServerConfig, options: &ResolverOpts)
        -> Self::ConnHandle;
}

/// Standard connection implements the default mechanism for creating new Connections
//#[derive (Clone)]
pub struct StandardConnection<T, U>{pub _tcp_marker: PhantomData<T>, pub _udp_marker: PhantomData<U>}

impl<T, U> Clone for StandardConnection<T, U> {
    fn clone(&self) -> Self {
        Self{_tcp_marker:PhantomData, _udp_marker:PhantomData}
    }
}

impl<T, U> ConnectionProvider for StandardConnection<T, U>
where
    T: 'static + Send + Sync + Unpin,
    U: 'static + Send + Sync + Unpin,
{
    type ConnHandle = ConnectionHandle<T, U>;

    /// Constructs an initial constructor for the ConnectionHandle to be used to establish a
    ///   future connection.
    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Self::ConnHandle {
        let dns_handle = match config.protocol {
            Protocol::Udp => {
                ConnectionHandleInner::<T, U>::Connect(Some(ConnectionHandleConnect::Udp {
                    socket_addr: config.socket_addr,
                    timeout: options.timeout,
                }))
            }
            Protocol::Tcp => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Tcp {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Tls {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
                tls_dns_name: config.tls_dns_name.clone().unwrap_or_default(),
                #[cfg(feature = "dns-over-rustls")]
                client_config: config.tls_config.clone(),
            })),
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => {
                ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Https {
                    socket_addr: config.socket_addr,
                    timeout: options.timeout,
                    tls_dns_name: config.tls_dns_name.clone().unwrap_or_default(),
                    #[cfg(feature = "dns-over-rustls")]
                    client_config: config.tls_config.clone(),
                }))
            }
            #[cfg(feature = "mdns")]
            Protocol::Mdns => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Mdns {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
        };

        ConnectionHandle(Arc::new(Mutex::new(dns_handle)))
    }
}

/// The variants of all supported connections for the Resolver
#[derive(Clone, Debug)]
pub(crate) enum ConnectionHandleConnect {
    Udp {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
    Tcp {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
    #[cfg(feature = "dns-over-tls")]
    Tls {
        socket_addr: SocketAddr,
        timeout: Duration,
        tls_dns_name: String,
        #[cfg(feature = "dns-over-rustls")]
        client_config: Option<TlsClientConfig>,
    },
    #[cfg(feature = "dns-over-https")]
    Https {
        socket_addr: SocketAddr,
        timeout: Duration,
        tls_dns_name: String,
        #[cfg(feature = "dns-over-rustls")]
        client_config: Option<TlsClientConfig>,
    },
    #[cfg(feature = "mdns")]
    Mdns {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
}

// TODO: rather than spawning here, return the background process, and rmove Background indirection.
impl ConnectionHandleConnect {
    /// Establishes the connection, this is allowed to perform network operations,
    ///   such as tokio::spawns of background tasks, etc.
    fn connect<T, U>(self) -> Result<ConnectionHandleConnected<T, U>, proto::error::ProtoError>
    where
        T: 'static + proto::tcp::Connect + Send,
        <T as proto::tcp::Connect>::Transport: std::marker::Unpin,
        U: 'static + proto::udp::UdpSocket + Send,
    {
        use self::ConnectionHandleConnect::*;

        debug!("connecting: {:?}", self);
        match self {
            Udp {
                socket_addr,
                timeout,
            } => {
                let stream = UdpClientStream::<U>::with_timeout(socket_addr, timeout);
                let (stream, handle) = DnsExchange::connect(stream);

                let stream = stream
                    .and_then(|stream| stream)
                    .map_err(|e| {
                        debug!("udp connection shutting down: {}", e);
                    })
                    .map(|_| ());
                let handle = BufDnsRequestStreamHandle::new(handle);

                tokio::spawn(stream.boxed());
                Ok(ConnectionHandleConnected::Udp(handle))
            }
            Tcp {
                socket_addr,
                timeout,
            } => {
                let (stream, handle) = TcpClientStream::<T>::with_timeout(socket_addr, timeout);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    Box::new(stream),
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream
                    .and_then(|stream| stream)
                    .map_err(|e| {
                        debug!("tcp connection shutting down: {}", e);
                    })
                    .map(|_| ());
                let handle = BufDnsRequestStreamHandle::new(handle);

                tokio::spawn(stream.boxed());
                Ok(ConnectionHandleConnected::Tcp(handle))
            }
            #[cfg(feature = "dns-over-tls")]
            Tls {
                socket_addr,
                timeout,
                tls_dns_name,
                #[cfg(feature = "dns-over-rustls")]
                client_config,
            } => {
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

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream
                    .and_then(|stream| stream)
                    .map_err(|e| {
                        debug!("tls connection shutting down: {}", e);
                    })
                    .map(|_| ());
                let handle = BufDnsRequestStreamHandle::new(handle);

                tokio::spawn(Box::pin(stream));
                Ok(ConnectionHandleConnected::Tcp(handle))
            }
            #[cfg(feature = "dns-over-https")]
            Https {
                socket_addr,
                // TODO: https needs timeout!
                timeout: _t,
                tls_dns_name,
                client_config,
            } => {
                let (stream, handle) =
                    crate::https::new_https_stream(socket_addr, tls_dns_name, client_config);

                let stream = stream
                    .and_then(|stream| stream)
                    .map_err(|e| {
                        debug!("https connection shutting down: {}", e);
                    })
                    .map(|_| ());

                tokio::spawn(Box::pin(stream));
                Ok(ConnectionHandleConnected::Https(handle))
            }
            #[cfg(feature = "mdns")]
            Mdns {
                socket_addr,
                timeout,
            } => {
                let (stream, handle) =
                    MdnsClientStream::new(socket_addr, MdnsQueryType::OneShot, None, None, None);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream
                    .and_then(|stream| stream)
                    .map_err(|e| {
                        debug!("mdns connection shutting down: {}", e);
                    })
                    .map(|_| ());
                let handle = BufDnsRequestStreamHandle::new(handle);

                tokio::spawn(Box::pin(stream));
                Ok(ConnectionHandleConnected::Tcp(handle))
            }
        }
    }
}

/// A representation of an established connection
enum ConnectionHandleConnected<T, U> {
    Udp(xfer::BufDnsRequestStreamHandle<UdpResponse>),
    Tcp(xfer::BufDnsRequestStreamHandle<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(xfer::BufDnsRequestStreamHandle<HttpsClientResponse>),
    #[allow(dead_code)]
    MarkerT(PhantomData<T>),
    #[allow(dead_code)]
    MarkerU(PhantomData<U>),
}

impl<T, U> Clone for ConnectionHandleConnected<T, U> {
    fn clone(&self) -> Self {
        match self {
            ConnectionHandleConnected::Udp(ref conn) => {
                ConnectionHandleConnected::Udp(conn.clone())
            }
            ConnectionHandleConnected::Tcp(ref conn) => {
                ConnectionHandleConnected::Tcp(conn.clone())
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionHandleConnected::Https(ref https) => {
                ConnectionHandleConnected::Https(https.clone())
            }
            ConnectionHandleConnected::MarkerT(_) => ConnectionHandleConnected::MarkerT(PhantomData),
            ConnectionHandleConnected::MarkerU(_) => ConnectionHandleConnected::MarkerU(PhantomData),
        }
    }
}

impl<T, U> DnsHandle for ConnectionHandleConnected<T, U>
where
    T: 'static + proto::tcp::Connect + Send + Unpin,
    <T as proto::tcp::Connect>::Transport: std::marker::Unpin,
    U: 'static + proto::udp::UdpSocket + Send + Unpin,
{
    type Response = ConnectionHandleResponseInner<T, U>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(
        &mut self,
        request: R,
    ) -> ConnectionHandleResponseInner<T, U> {
        match self {
            ConnectionHandleConnected::Udp(ref mut conn) => {
                ConnectionHandleResponseInner::Udp(conn.send(request))
            }
            ConnectionHandleConnected::Tcp(ref mut conn) => {
                ConnectionHandleResponseInner::Tcp(conn.send(request))
            }
            #[cfg(feature = "dns-over-https")]
            ConnectionHandleConnected::Https(ref mut https) => {
                ConnectionHandleResponseInner::Https(https.send(request))
            }
            ConnectionHandleConnected::MarkerT(_) => unreachable!(),
            ConnectionHandleConnected::MarkerU(_) => unreachable!(),
        }
    }
}

/// Allows us to wrap a connection that is either pending or already connected
enum ConnectionHandleInner<T, U> {
    //    Connect(Option<ConnectionHandleConnect>),
    Connect(Option<ConnectionHandleConnect>),
    Connected(ConnectionHandleConnected<T, U>),
}

impl<T, U> Clone for ConnectionHandleInner<T, U> {
    fn clone(&self) -> Self {
        match self {
            ConnectionHandleInner::Connect(ref conn) => {
                match conn {
                    Some(x) => ConnectionHandleInner::Connect(Some(x.clone())),
                    None => ConnectionHandleInner::Connect(None)
                }
            }
            ConnectionHandleInner::Connected(ref conned) => {
                ConnectionHandleInner::Connected(conned.clone())
            }
        }
    }
}

impl<T, U> ConnectionHandleInner<T, U>
where
    T: 'static + proto::tcp::Connect + Send + Unpin,
    U: 'static + proto::udp::UdpSocket + Send + Unpin,
    <T as proto::tcp::Connect>::Transport: std::marker::Unpin,
{
    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(
        &mut self,
        request: R,
    ) -> ConnectionHandleResponseInner<T, U> {
        loop {
            let connected: Result<ConnectionHandleConnected<T, U>, proto::error::ProtoError> =
                match self {
                    // still need to connect, drop through
                    ConnectionHandleInner::Connect(conn) => {
                        conn.take().expect("already connected?").connect::<T, U>()
                    }
                    ConnectionHandleInner::Connected(conn) => return conn.send(request),
                };

            match connected {
                Ok(connected) => *self = ConnectionHandleInner::Connected(connected),
                Err(e) => return ConnectionHandleResponseInner::ProtoError(Some(e)),
            };
            // continue to return on send...
        }
    }
}

/// ConnectionHandle is used for sending DNS requests to a specific upstream DNS resolver
pub struct ConnectionHandle<T, U>(Arc<Mutex<ConnectionHandleInner<T, U>>>);

impl<T, U> Clone for ConnectionHandle<T, U> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, U> DnsHandle for ConnectionHandle<T, U>
where
    T: 'static + proto::tcp::Connect + Send + Unpin,
    <T as proto::tcp::Connect>::Transport: Unpin,
    U: 'static + proto::udp::UdpSocket + Send + Unpin,
{
    type Response = ConnectionHandleResponse<T, U>;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponse<T, U> {
        ConnectionHandleResponse(ConnectionHandleResponseInner::ConnectAndRequest {
            conn: self.clone(),
            request: Some(request.into()),
        })
    }
}

/// A wrapper type to switch over a connection that still needs to be made, or is already established
#[must_use = "futures do nothing unless polled"]
enum ConnectionHandleResponseInner<T, U> {
    ConnectAndRequest {
        conn: ConnectionHandle<T, U>,
        request: Option<DnsRequest>,
    },
    Udp(xfer::OneshotDnsResponseReceiver<UdpResponse>),
    Tcp(xfer::OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(xfer::OneshotDnsResponseReceiver<HttpsClientResponse>),
    ProtoError(Option<proto::error::ProtoError>),
    #[allow(dead_code)]
    MarkerT(PhantomData<T>),
    #[allow(dead_code)]
    MarkerU(PhantomData<U>),
}

impl<T, U> Future for ConnectionHandleResponseInner<T, U>
where
    T: 'static + proto::tcp::Connect + Send + Unpin,
    <T as proto::tcp::Connect>::Transport: std::marker::Unpin,
    U: 'static + proto::udp::UdpSocket + Send + Unpin,
{
    type Output = Result<DnsResponse, proto::error::ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        use self::ConnectionHandleResponseInner::*;

        trace!("polling response inner");
        loop {
            *self = match *self {
                // we still need to check the connection
                ConnectAndRequest {
                    ref conn,
                    ref mut request,
                } => match conn.0.lock() {
                    Ok(mut c) => c.send(request.take().expect("already sent request?")),
                    Err(e) => ProtoError(Some(proto::error::ProtoError::from(e))),
                },
                Udp(ref mut resp) => return resp.poll_unpin(cx),
                Tcp(ref mut resp) => return resp.poll_unpin(cx),
                #[cfg(feature = "dns-over-https")]
                Https(ref mut https) => return https.poll_unpin(cx),
                ProtoError(ref mut e) => {
                    return Poll::Ready(Err(e
                        .take()
                        .expect("futures cannot be polled once complete")));
                }
                _ => unreachable!(),
            };

            // ok, connected, loop around and use poll the actual send request
        }
    }
}

/// A future response from a DNS request.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionHandleResponse<T, U>(ConnectionHandleResponseInner<T, U>);

impl<T, U> Future for ConnectionHandleResponse<T, U>
where
    T: 'static + proto::tcp::Connect + Send + Unpin,
    <T as proto::tcp::Connect>::Transport: std::marker::Unpin,
    U: 'static + proto::udp::UdpSocket + Send + Unpin,
{
    type Output = Result<DnsResponse, proto::error::ProtoError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}
