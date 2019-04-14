// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{Future, Poll};
use tokio_executor::{DefaultExecutor, Executor};

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
use trust_dns_https;

use config::{NameServerConfig, Protocol, ResolverOpts};

/// A type to allow for custom ConnectionProviders. Needed mainly for mocking purposes.
pub trait ConnectionProvider: 'static + Clone + Send + Sync {
    type ConnHandle;

    /// The returned handle should
    fn new_connection(&self, config: &NameServerConfig, options: &ResolverOpts)
        -> Self::ConnHandle;
}

/// Standard connection implements the default mechanism for creating new Connections
#[derive(Clone)]
pub struct StandardConnection;

impl ConnectionProvider for StandardConnection {
    type ConnHandle = ConnectionHandle;

    /// Constructs an initial constructor for the ConnectionHandle to be used to establish a
    ///   future connection.
    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Self::ConnHandle {
        let dns_handle = match config.protocol {
            Protocol::Udp => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Udp {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
            Protocol::Tcp => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Tcp {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
            })),
            #[cfg(feature = "dns-over-tls")]
            Protocol::Tls => ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Tls {
                socket_addr: config.socket_addr,
                timeout: options.timeout,
                tls_dns_name: config.tls_dns_name.clone().unwrap_or_default(),
            })),
            #[cfg(feature = "dns-over-https")]
            Protocol::Https => {
                ConnectionHandleInner::Connect(Some(ConnectionHandleConnect::Https {
                    socket_addr: config.socket_addr,
                    timeout: options.timeout,
                    tls_dns_name: config.tls_dns_name.clone().unwrap_or_default(),
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
#[derive(Debug)]
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
    },
    #[cfg(feature = "dns-over-https")]
    Https {
        socket_addr: SocketAddr,
        timeout: Duration,
        tls_dns_name: String,
    },
    #[cfg(feature = "mdns")]
    Mdns {
        socket_addr: SocketAddr,
        timeout: Duration,
    },
}

impl ConnectionHandleConnect {
    /// Establishes the connection, this is allowed to perform network operations,
    ///   suchas tokio::spawns of background tasks, etc.
    fn connect(self) -> Result<ConnectionHandleConnected, proto::error::ProtoError> {
        use self::ConnectionHandleConnect::*;

        debug!("connecting: {:?}", self);
        match self {
            Udp {
                socket_addr,
                timeout,
            } => {
                let stream = UdpClientStream::with_timeout(socket_addr, timeout);
                let (stream, handle) = DnsExchange::connect(stream);

                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("udp connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::Udp(handle))
            }
            Tcp {
                socket_addr,
                timeout,
            } => {
                let (stream, handle) = TcpClientStream::with_timeout(socket_addr, timeout);
                // TODO: need config for Signer...
                let dns_conn = DnsMultiplexer::with_timeout(
                    Box::new(stream),
                    handle,
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("tcp connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::Tcp(handle))
            }
            #[cfg(feature = "dns-over-tls")]
            Tls {
                socket_addr,
                timeout,
                tls_dns_name,
            } => {
                let (stream, handle) = ::tls::new_tls_stream(socket_addr, tls_dns_name);
                let dns_conn = DnsMultiplexer::with_timeout(
                    stream,
                    Box::new(handle),
                    timeout,
                    NoopMessageFinalizer::new(),
                );

                let (stream, handle) = DnsExchange::connect(dns_conn);
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("tls connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::Tcp(handle))
            }
            #[cfg(feature = "dns-over-https")]
            Https {
                socket_addr,
                // TODO: https needs timeout!
                timeout: _t,
                tls_dns_name,
            } => {
                let (stream, handle) = ::https::new_https_stream(socket_addr, tls_dns_name);

                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("https connection shutting down: {}", e);
                });

                DefaultExecutor::current().spawn(Box::new(stream))?;
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
                let stream = stream.and_then(|stream| stream).map_err(|e| {
                    debug!("mdns connection shutting down: {}", e);
                });
                let handle = BufDnsRequestStreamHandle::new(handle);

                DefaultExecutor::current().spawn(Box::new(stream))?;
                Ok(ConnectionHandleConnected::Tcp(handle))
            }
        }
    }
}

/// A representation of an established connection
#[derive(Clone)]
enum ConnectionHandleConnected {
    Udp(xfer::BufDnsRequestStreamHandle<UdpResponse>),
    Tcp(xfer::BufDnsRequestStreamHandle<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(xfer::BufDnsRequestStreamHandle<trust_dns_https::HttpsSerialResponse>),
}

impl DnsHandle for ConnectionHandleConnected {
    type Response = ConnectionHandleResponseInner;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponseInner {
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
        }
    }
}

/// Allows us to wrap a connection that is either pending or already connected
enum ConnectionHandleInner {
    Connect(Option<ConnectionHandleConnect>),
    Connected(ConnectionHandleConnected),
}

impl ConnectionHandleInner {
    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponseInner {
        loop {
            let connected: Result<ConnectionHandleConnected, proto::error::ProtoError> = match self
            {
                // still need to connect, drop through
                ConnectionHandleInner::Connect(conn) => {
                    conn.take().expect("already connected?").connect()
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
#[derive(Clone)]
pub struct ConnectionHandle(Arc<Mutex<ConnectionHandleInner>>);

impl DnsHandle for ConnectionHandle {
    type Response = ConnectionHandleResponse;

    fn send<R: Into<DnsRequest>>(&mut self, request: R) -> ConnectionHandleResponse {
        ConnectionHandleResponse(ConnectionHandleResponseInner::ConnectAndRequest {
            conn: self.clone(),
            request: Some(request.into()),
        })
    }
}

/// A wrapper type to switch over a connection that still needs to be made, or is already established
#[must_use = "futures do nothing unless polled"]
enum ConnectionHandleResponseInner {
    ConnectAndRequest {
        conn: ConnectionHandle,
        request: Option<DnsRequest>,
    },
    Udp(xfer::OneshotDnsResponseReceiver<UdpResponse>),
    Tcp(xfer::OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>),
    #[cfg(feature = "dns-over-https")]
    Https(xfer::OneshotDnsResponseReceiver<trust_dns_https::HttpsSerialResponse>),
    ProtoError(Option<proto::error::ProtoError>),
}

impl Future for ConnectionHandleResponseInner {
    type Item = DnsResponse;
    type Error = proto::error::ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        use self::ConnectionHandleResponseInner::*;

        trace!("polling response inner");
        loop {
            *self = match self {
                // we still need to check the connection
                ConnectAndRequest {
                    ref conn,
                    ref mut request,
                } => match conn.0.lock() {
                    Ok(mut c) => c.send(request.take().expect("already sent request?")),
                    Err(e) => ProtoError(Some(proto::error::ProtoError::from(e))),
                },
                Udp(ref mut resp) => return resp.poll(),
                Tcp(ref mut resp) => return resp.poll(),
                #[cfg(feature = "dns-over-https")]
                Https(ref mut https) => return https.poll(),
                ProtoError(ref mut e) => {
                    return Err(e.take().expect("futures cannot be polled once complete"))
                }
            };

            // ok, connected, loop around and use poll the actual send request
        }
    }
}

/// A future response from a DNS request.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionHandleResponse(ConnectionHandleResponseInner);

impl Future for ConnectionHandleResponse {
    type Item = DnsResponse;
    type Error = proto::error::ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}
