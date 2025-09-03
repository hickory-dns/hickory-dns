// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `Server` component for hosting a domain name servers operations.

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "__tls")]
use crate::proto::rustls::tls_from_stream;
use bytes::Bytes;
use futures_util::StreamExt;
use ipnet::IpNet;
#[cfg(feature = "__tls")]
use rustls::{ServerConfig, server::ResolvesServerCert};
#[cfg(feature = "__tls")]
use tokio::time::timeout;
use tokio::{net, task::JoinSet};
#[cfg(feature = "__tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[cfg(feature = "__h3")]
use crate::proto::h3::h3_server::H3Server;
#[cfg(feature = "__quic")]
use crate::proto::quic::QuicServer;
#[cfg(feature = "__tls")]
use crate::proto::rustls::default_provider;
use crate::{
    access::AccessControl,
    proto::{
        BufDnsStreamHandle, ProtoError,
        op::{Header, LowerQuery, MessageType, ResponseCode, SerialMessage},
        rr::Record,
        runtime::TokioTime,
        runtime::{TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd},
        serialize::binary::{BinDecodable, BinDecoder},
        tcp::TcpStream,
        udp::UdpStream,
        xfer::Protocol,
    },
    zone_handler::{MessageRequest, MessageResponseBuilder, Queries},
};

#[cfg(feature = "__https")]
mod h2_handler;
#[cfg(feature = "__h3")]
mod h3_handler;
#[cfg(feature = "__quic")]
mod quic_handler;
mod request_handler;
pub use request_handler::{Request, RequestHandler, RequestInfo, ResponseInfo};
mod response_handler;
pub use response_handler::{ResponseHandle, ResponseHandler};
#[cfg(feature = "metrics")]
mod metrics;
#[cfg(feature = "metrics")]
use metrics::ResponseHandlerMetrics;
mod timeout_stream;
pub use timeout_stream::TimeoutStream;

// TODO, would be nice to have a Slab for buffers here...
/// A Futures based implementation of a DNS server
pub struct Server<T: RequestHandler> {
    context: Arc<ServerContext<T>>,
    join_set: JoinSet<Result<(), ProtoError>>,
}

impl<T: RequestHandler> Server<T> {
    /// Creates a new ServerFuture with the specified Handler.
    pub fn new(handler: T) -> Self {
        Self::with_access(handler, &[], &[])
    }

    /// Creates a new ServerFuture with the specified Handler and denied/allowed networks
    pub fn with_access(handler: T, denied_networks: &[IpNet], allowed_networks: &[IpNet]) -> Self {
        let mut access = AccessControl::default();
        access.insert_deny(denied_networks);
        access.insert_allow(allowed_networks);

        Self {
            context: Arc::new(ServerContext {
                handler,
                access,
                shutdown: CancellationToken::new(),
            }),
            join_set: JoinSet::new(),
        }
    }

    /// Register a UDP socket. Should be bound before calling this function.
    pub fn register_socket(&mut self, socket: net::UdpSocket) {
        self.join_set
            .spawn(handle_udp(socket, self.context.clone()));
    }

    /// Register a TcpListener to the Server. This should already be bound to either an IPv6 or an
    ///  IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    pub fn register_listener(&mut self, listener: net::TcpListener, timeout: Duration) {
        self.join_set
            .spawn(handle_tcp(listener, timeout, self.context.clone()));
    }

    /// Register a TlsListener to the Server. The TlsListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoT ALPN protocol
    /// enabled.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `tls_config` - rustls server config
    #[cfg(feature = "__tls")]
    pub fn register_tls_listener_with_tls_config(
        &mut self,
        listener: net::TcpListener,
        handshake_timeout: Duration,
        tls_config: Arc<ServerConfig>,
    ) -> io::Result<()> {
        self.join_set.spawn(handle_tls(
            listener,
            tls_config,
            handshake_timeout,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a TlsListener to the Server by providing a rustls `ResolvesServerCert`. The
    /// TlsListener should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `server_cert_resolver` - resolver for the certificate and key used to announce to clients
    #[cfg(feature = "__tls")]
    pub fn register_tls_listener(
        &mut self,
        listener: net::TcpListener,
        timeout: Duration,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> io::Result<()> {
        Self::register_tls_listener_with_tls_config(
            self,
            listener,
            timeout,
            Arc::new(default_tls_server_config(b"dot", server_cert_resolver)?),
        )
    }

    /// Register a TcpListener for HTTPS (h2) to the Server for supporting DoH (DNS-over-HTTPS). The TcpListener should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `server_cert_resolver` - resolver for the certificate and key used to announce to clients
    /// * `dns_hostname` - the DNS hostname of the H2 server.
    /// * `http_endpoint` - the HTTP endpoint of the H2 server.
    #[cfg(feature = "__https")]
    pub fn register_https_listener(
        &mut self,
        listener: net::TcpListener,
        // TODO: need to set a timeout between requests.
        handshake_timeout: Duration,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
        dns_hostname: Option<String>,
        http_endpoint: String,
    ) -> io::Result<()> {
        self.join_set.spawn(h2_handler::handle_h2(
            listener,
            handshake_timeout,
            server_cert_resolver,
            dns_hostname,
            http_endpoint,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a TcpListener for HTTPS (h2) for supporting DoH with the given TLS config.
    ///
    /// The TcpListener should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoH ALPN protocol
    /// enabled.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `handshake_timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `tls_config` - a customized `ServerConfig` to use for TLS.
    /// * `dns_hostname` - the DNS hostname of the H2 server.
    /// * `http_endpoint` - the HTTP endpoint of the H2 server.
    #[cfg(feature = "__https")]
    pub fn register_https_listener_with_tls_config(
        &mut self,
        listener: net::TcpListener,
        // TODO: need to set a timeout between requests.
        handshake_timeout: Duration,
        tls_config: Arc<ServerConfig>,
        dns_hostname: Option<String>,
        http_endpoint: String,
    ) -> io::Result<()> {
        self.join_set.spawn(h2_handler::handle_h2_with_acceptor(
            listener,
            handshake_timeout,
            TlsAcceptor::from(tls_config),
            dns_hostname,
            http_endpoint,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a UdpSocket to the Server for supporting DoQ (DNS-over-QUIC). The UdpSocket should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `socket` - a bound UDP socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `server_cert_resolver` - resolver for certificate and key used to announce to clients
    /// * `dns_hostname` - the DNS hostname of the DoQ server.
    #[cfg(feature = "__quic")]
    pub fn register_quic_listener(
        &mut self,
        socket: net::UdpSocket,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
        dns_hostname: Option<String>,
    ) -> io::Result<()> {
        let cx = self.context.clone();
        self.join_set.spawn(quic_handler::handle_quic(
            socket,
            server_cert_resolver,
            dns_hostname,
            cx,
        ));
        Ok(())
    }

    /// Register a UdpSocket for supporting DoQ (DNS-over-QUIC) with the provided TLS config.
    ///
    /// The UdpSocket should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoQ ALPN protocol
    /// enabled.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `socket` - a bound UDP socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `tls_config` - a customized ServerConfig to use for TLS.
    /// * `dns_hostname` - the DNS hostname of the DoQ server.
    #[cfg(feature = "__quic")]
    pub fn register_quic_listener_and_tls_config(
        &mut self,
        socket: net::UdpSocket,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        tls_config: Arc<ServerConfig>,
        dns_hostname: Option<String>,
    ) -> io::Result<()> {
        let cx = self.context.clone();

        self.join_set.spawn(quic_handler::handle_quic_with_server(
            QuicServer::with_socket_and_tls_config(socket, tls_config)?,
            dns_hostname,
            cx,
        ));
        Ok(())
    }

    /// Register a UdpSocket to the Server for supporting DoH3 (DNS-over-HTTP/3). The UdpSocket should already be bound to either an
    /// IPv6 or an IPv4 address.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `server_cert_resolver` - resolver for certificate and key used to announce to clients
    #[cfg(feature = "__h3")]
    pub fn register_h3_listener(
        &mut self,
        socket: net::UdpSocket,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
        dns_hostname: Option<String>,
    ) -> io::Result<()> {
        self.join_set.spawn(h3_handler::handle_h3(
            socket,
            server_cert_resolver,
            dns_hostname,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Register a UdpSocket for supporting DoH3 (DNS-over-HTTP/3) with the specified TLS config.
    ///
    /// The UdpSocket should already be bound to either an IPv6 or an IPv4 address.
    ///
    /// The TLS `ServerConfig` should be configured with TLS 1.3 support and the DoH3 ALPN protocol
    /// enabled.
    ///
    /// To make the server more resilient to DOS issues, there is a timeout. Care should be taken
    ///  to not make this too low depending on use cases.
    ///
    /// # Arguments
    /// * `listener` - a bound TCP (needs to be on a different port from standard TCP connections) socket
    /// * `timeout` - timeout duration of incoming requests, any connection that does not send
    ///   requests within this time period will be closed. In the future it should be
    ///   possible to create long-lived queries, but these should be from trusted sources
    ///   only, this would require some type of whitelisting.
    /// * `tls_config` - a customized ServerConfig to use for TLS.
    #[cfg(feature = "__h3")]
    pub fn register_h3_listener_with_tls_config(
        &mut self,
        socket: net::UdpSocket,
        // TODO: need to set a timeout between requests.
        _timeout: Duration,
        tls_config: Arc<ServerConfig>,
        dns_hostname: Option<String>,
    ) -> io::Result<()> {
        self.join_set.spawn(h3_handler::handle_h3_with_server(
            H3Server::with_socket_and_tls_config(socket, tls_config)?,
            dns_hostname,
            self.context.clone(),
        ));
        Ok(())
    }

    /// Triggers a graceful shutdown the server. All background tasks will stop accepting
    /// new connections and the returned future will complete once all tasks have terminated.
    pub async fn shutdown_gracefully(&mut self) -> Result<(), ProtoError> {
        self.context.shutdown.cancel();

        // Wait for the server to complete.
        self.block_until_done().await
    }

    /// Returns a reference to the [`CancellationToken`] used to gracefully shut down the server.
    ///
    /// Once cancellation is requested, all background tasks will stop accepting new connections,
    /// and `block_until_done()` will complete once all tasks have terminated.
    pub fn shutdown_token(&self) -> &CancellationToken {
        &self.context.shutdown
    }

    /// This will run until all background tasks complete. If one or more tasks return an error,
    /// one will be chosen as the returned error for this future.
    pub async fn block_until_done(&mut self) -> Result<(), ProtoError> {
        if self.join_set.is_empty() {
            warn!("block_until_done called with no pending tasks");
            return Ok(());
        }

        let mut out = Ok(());
        while let Some(join_result) = self.join_set.join_next().await {
            match join_result {
                Ok(Ok(())) => continue,
                Ok(Err(e)) => out = Err(e),
                Err(e) => return Err(ProtoError::from(format!("internal error in spawn: {e}"))),
            }
        }

        out
    }
}

async fn handle_udp(
    socket: net::UdpSocket,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    debug!("registering udp: {:?}", socket);

    // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
    //   the address used is acquired from the inbound queries
    let (mut stream, stream_handle) =
        UdpStream::<TokioRuntimeProvider>::with_bound(socket, ([127, 255, 255, 254], 0).into());

    let mut inner_join_set = JoinSet::new();
    loop {
        let message = tokio::select! {
            message = stream.next() => match message {
                None => break,
                Some(message) => message,
            },
            _ = cx.shutdown.cancelled() => break,
        };

        let message = match message {
            Err(error) => {
                warn!(%error, "error receiving message on udp_socket");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
            Ok(message) => message,
        };

        let src_addr = message.addr();
        debug!("received udp request from: {}", src_addr);

        // verify that the src address is safe for responses
        if let Err(e) = sanitize_src_address(src_addr) {
            warn!(
                "address can not be responded to {src_addr}: {e}",
                src_addr = src_addr,
                e = e
            );
            continue;
        }

        let cx = cx.clone();
        let stream_handle = stream_handle.with_remote_addr(src_addr);
        inner_join_set.spawn(async move {
            cx.handle_raw_request(message, Protocol::Udp, stream_handle)
                .await;
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
        Err(ProtoError::from("unexpected close of UDP socket"))
    }
}

async fn handle_tcp(
    listener: net::TcpListener,
    timeout: Duration,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    debug!("register tcp: {listener:?}");
    let mut inner_join_set = JoinSet::new();
    loop {
        let (tcp_stream, src_addr) = tokio::select! {
            tcp_stream = listener.accept() => match tcp_stream {
                Ok((t, s)) => (t, s),
                Err(error) => {
                    debug!(%error, "error receiving TCP tcp_stream error");
                    if is_unrecoverable_socket_error(&error) {
                        break;
                    }
                    continue;
                },
            },
            _ = cx.shutdown.cancelled() => {
                // A graceful shutdown was initiated. Break out of the loop.
                break;
            },
        };

        // verify that the src address is safe for responses
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %src_addr, %error,
                "address can not be responded to (TCP)",
            );
            continue;
        }

        // and spawn to the io_loop
        let cx = cx.clone();
        inner_join_set.spawn(async move {
            debug!(%src_addr, "accepted TCP request");
            // take the created stream...
            let (buf_stream, stream_handle) =
                TcpStream::from_stream(AsyncIoTokioAsStd(tcp_stream), src_addr);
            let mut timeout_stream = TimeoutStream::new(buf_stream, timeout);

            while let Some(message) = timeout_stream.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        debug!(%src_addr, %error, "error in TCP request stream");
                        // we're going to bail on this connection...
                        return;
                    }
                };

                // we don't spawn here to limit clients from getting too many resources
                cx.handle_raw_request(message, Protocol::Tcp, stream_handle.clone())
                    .await;
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(ProtoError::from("unexpected close of socket"))
    }
}

#[cfg(feature = "__tls")]
async fn handle_tls(
    listener: net::TcpListener,
    tls_config: Arc<ServerConfig>,
    handshake_timeout: Duration,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), ProtoError> {
    debug!(?listener, "registered tls");
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let mut inner_join_set = JoinSet::new();
    loop {
        let (tcp_stream, src_addr) = tokio::select! {
            tcp_stream = listener.accept() => match tcp_stream {
                Ok((t, s)) => (t, s),
                Err(error) => {
                    debug!(%error, "error receiving TLS tcp_stream error");
                    if is_unrecoverable_socket_error(&error) {
                        break;
                    }
                    continue;
                },
            },
            _ = cx.shutdown.cancelled() => {
                // A graceful shutdown was initiated. Break out of the loop.
                break;
            },
        };

        // verify that the src address is safe for responses
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %src_addr, %error,
                "address can not be responded to (TLS)",
            );
            continue;
        }

        let cx = cx.clone();
        let tls_acceptor = tls_acceptor.clone();
        // kick out to a different task immediately, let them do the TLS handshake
        inner_join_set.spawn(async move {
            debug!(%src_addr, "starting TLS request");

            // perform the TLS
            let Ok(tls_stream) = timeout(handshake_timeout, tls_acceptor.accept(tcp_stream)).await
            else {
                warn!("tls timeout expired during handshake");
                return;
            };

            let tls_stream = match tls_stream {
                Ok(tls_stream) => AsyncIoTokioAsStd(tls_stream),
                Err(error) => {
                    debug!(%src_addr, %error, "tls handshake error");
                    return;
                }
            };
            debug!(%src_addr, "accepted TLS request");
            let (buf_stream, stream_handle) = tls_from_stream(tls_stream, src_addr);
            let mut timeout_stream = TimeoutStream::new(buf_stream, handshake_timeout);
            while let Some(message) = timeout_stream.next().await {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        debug!(
                            %src_addr, %error,
                            "error in TLS request stream",
                        );

                        // kill this connection
                        return;
                    }
                };

                cx.handle_raw_request(message, Protocol::Tls, stream_handle.clone())
                    .await;
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(ProtoError::from("unexpected close of socket"))
    }
}

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
fn reap_tasks(join_set: &mut JoinSet<()>) {
    while join_set.try_join_next().is_some() {}
}

/// Construct a default `ServerConfig` for the given ALPN protocol and server cert resolver.
#[cfg(feature = "__tls")]
pub fn default_tls_server_config(
    protocol: &[u8],
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(server_cert_resolver);

    config.alpn_protocols = vec![protocol.to_vec()];

    Ok(config)
}

#[derive(Clone)]
struct ReportingResponseHandler<R: ResponseHandler> {
    request_header: Header,
    queries: Vec<LowerQuery>,
    protocol: Protocol,
    src_addr: SocketAddr,
    handler: R,
    #[cfg(feature = "metrics")]
    metrics: ResponseHandlerMetrics,
}

#[async_trait::async_trait]
impl<R: ResponseHandler> ResponseHandler for ReportingResponseHandler<R> {
    async fn send_response<'a>(
        &mut self,
        response: crate::zone_handler::MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let response_info = self.handler.send_response(response).await?;

        let id = self.request_header.id();
        let rid = response_info.id();
        if id != rid {
            warn!("request id:{id} does not match response id:{rid}");
            debug_assert_eq!(id, rid, "request id and response id should match");
        }

        let rflags = response_info.flags();
        let answer_count = response_info.answer_count();
        let authority_count = response_info.authority_count();
        let additional_count = response_info.additional_count();
        let response_code = response_info.response_code();

        info!(
            "request:{id} src:{proto}://{addr}#{port} {op} qflags:{qflags} response:{code:?} rr:{answers}/{authorities}/{additionals} rflags:{rflags}",
            id = rid,
            proto = self.protocol,
            addr = self.src_addr.ip(),
            port = self.src_addr.port(),
            op = self.request_header.op_code(),
            qflags = self.request_header.flags(),
            code = response_code,
            answers = answer_count,
            authorities = authority_count,
            additionals = additional_count,
            rflags = rflags
        );
        for query in self.queries.iter() {
            info!(
                "query:{query}:{qtype}:{class}",
                query = query.name(),
                qtype = query.query_type(),
                class = query.query_class()
            );
        }

        #[cfg(feature = "metrics")]
        self.metrics.update(self, &response_info);

        Ok(response_info)
    }
}

#[cfg(feature = "metrics")]
impl ResponseHandlerMetrics {
    fn update(
        &self,
        response_handler: &ReportingResponseHandler<impl ResponseHandler>,
        response_info: &ResponseInfo,
    ) {
        self.proto.increment(&response_handler.protocol);
        self.operation
            .increment(&response_handler.request_header.op_code());
        self.request_flags
            .increment(&response_handler.request_header);

        self.response_code.increment(&response_info.response_code());
        self.response_flags.increment(response_info);
    }
}

struct ServerContext<T> {
    handler: T,
    access: AccessControl,
    shutdown: CancellationToken,
}

impl<T: RequestHandler> ServerContext<T> {
    async fn handle_raw_request(
        &self,
        message: SerialMessage,
        protocol: Protocol,
        response_handler: BufDnsStreamHandle,
    ) {
        let (message, src_addr) = message.into_parts();
        let response_handler = ResponseHandle::new(src_addr, response_handler, protocol);

        self.handle_request(Bytes::from(message), src_addr, protocol, response_handler)
            .await;
    }

    async fn handle_request(
        &self,
        message_bytes: Bytes,
        src_addr: SocketAddr,
        protocol: Protocol,
        response_handler: impl ResponseHandler,
    ) {
        let mut decoder = BinDecoder::new(&message_bytes);
        if !self.access.allow(src_addr.ip()) {
            info!(
                "request:Refused src:{proto}://{addr}#{port}",
                proto = protocol,
                addr = src_addr.ip(),
                port = src_addr.port(),
            );

            let Ok(header) = Header::read(&mut decoder) else {
                // This will only fail if the message is less than twelve bytes long. Such messages are
                // definitely not valid DNS queries, so it should be fine to return without sending a
                // response.
                return;
            };
            let queries = match Queries::read(&mut decoder, header.query_count() as usize) {
                Ok(queries) => queries,
                Err(_) => Queries::empty(),
            };
            error_response_handler(
                protocol,
                src_addr,
                header,
                queries,
                ResponseCode::Refused,
                "request refused",
                response_handler,
            )
            .await;

            return;
        }

        // Attempt to decode the message
        let request = match MessageRequest::read(&mut decoder) {
            Ok(message) => Request {
                message,
                raw: message_bytes,
                src: src_addr,
                protocol,
            },
            Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
                // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
                let (header, error) = kind
                    .into_form_error()
                    .expect("as form_error already confirmed this is a FormError");
                let queries = Queries::empty();

                error_response_handler(
                    protocol,
                    src_addr,
                    header,
                    queries,
                    ResponseCode::FormErr,
                    error,
                    response_handler,
                )
                .await;

                return;
            }
            Err(error) => {
                info!(
                    "request:Failed src:{proto}://{addr}#{port} error:{error}",
                    proto = protocol,
                    addr = src_addr.ip(),
                    port = src_addr.port(),
                );
                return;
            }
        };

        if request.message.message_type() == MessageType::Response {
            // Don't process response messages to avoid DoS attacks from reflection.
            return;
        }

        let id = request.message.id();
        let qflags = request.message.header().flags();
        let qop_code = request.message.op_code();
        let message_type = request.message.message_type();
        let is_dnssec = request
            .message
            .edns()
            .is_some_and(|edns| edns.flags().dnssec_ok);

        debug!(
            "request:{id} src:{proto}://{addr}#{port} type:{message_type} dnssec:{is_dnssec} {op} qflags:{qflags}",
            id = id,
            proto = request.protocol(),
            addr = request.src().ip(),
            port = request.src().port(),
            message_type = message_type,
            is_dnssec = is_dnssec,
            op = qop_code,
            qflags = qflags
        );
        for query in request.queries().iter() {
            debug!(
                "query:{query}:{qtype}:{class}",
                query = query.name(),
                qtype = query.query_type(),
                class = query.query_class()
            );
        }

        // The reporter will handle making sure to log the result of the request
        let queries = request.queries().to_vec();
        let reporter = ReportingResponseHandler {
            request_header: *request.header(),
            queries,
            protocol: request.protocol(),
            src_addr: request.src(),
            handler: response_handler,
            #[cfg(feature = "metrics")]
            metrics: ResponseHandlerMetrics::default(),
        };

        self.handler
            .handle_request::<_, TokioTime>(&request, reporter)
            .await;
    }
}

// method to return an error to the client
async fn error_response_handler(
    protocol: Protocol,
    src_addr: SocketAddr,
    header: Header,
    queries: Queries,
    response_code: ResponseCode,
    error: impl fmt::Display,
    response_handler: impl ResponseHandler,
) {
    // debug for more info on why the message parsing failed
    debug!(
        "request:{id} src:{proto}://{addr}#{port} type:{message_type} {op}:{response_code}:{error}",
        id = header.id(),
        proto = protocol,
        addr = src_addr.ip(),
        port = src_addr.port(),
        message_type = header.message_type(),
        op = header.op_code(),
        response_code = response_code,
        error = error,
    );

    // The reporter will handle making sure to log the result of the request
    let mut reporter = ReportingResponseHandler {
        request_header: header,
        queries: queries.queries().to_vec(),
        protocol,
        src_addr,
        handler: response_handler,
        #[cfg(feature = "metrics")]
        metrics: ResponseHandlerMetrics::default(),
    };

    let response = MessageResponseBuilder::new(&queries, None);
    let result = reporter
        .send_response(response.error_msg(&header, response_code))
        .await;

    if let Err(error) = result {
        warn!(%error, "failed to return FormError to client");
    }
}

/// Checks if the IP address is safe for returning messages
///
/// Examples of unsafe addresses are any with a port of `0`
///
/// # Returns
///
/// Error if the address should not be used for returned requests
fn sanitize_src_address(src: SocketAddr) -> Result<(), String> {
    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    if src.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {src}"));
    }

    fn verify_v4(src: Ipv4Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v4 addr: {src}"));
        }

        if src.is_broadcast() {
            return Err(format!("cannot respond to broadcast v4 addr: {src}"));
        }

        // TODO: add check for is_reserved when that stabilizes

        Ok(())
    }

    fn verify_v6(src: Ipv6Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v6 addr: {src}"));
        }

        Ok(())
    }

    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    match src.ip() {
        IpAddr::V4(v4) => verify_v4(v4),
        IpAddr::V6(v6) => verify_v6(v6),
    }
}

fn is_unrecoverable_socket_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_handler::Catalog;
    use futures_util::future;
    #[cfg(feature = "__tls")]
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        sign::{CertifiedKey, SingleCertAndKey},
    };
    use std::net::SocketAddr;
    use test_support::subscribe;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::timeout;

    #[tokio::test]
    async fn abort() {
        subscribe();

        let endpoints = Endpoints::new().await;

        let endpoints2 = endpoints.clone();
        let (abortable, abort_handle) = future::abortable(async move {
            let mut server_future = Server::new(Catalog::new());
            endpoints2.register(&mut server_future).await;
            server_future.block_until_done().await
        });

        abort_handle.abort();
        abortable.await.expect_err("expected abort");

        endpoints.rebind_all().await;
    }

    #[tokio::test]
    async fn graceful_shutdown() {
        subscribe();
        let mut server_future = Server::new(Catalog::new());
        let endpoints = Endpoints::new().await;
        endpoints.register(&mut server_future).await;

        timeout(Duration::from_secs(2), server_future.shutdown_gracefully())
            .await
            .expect("timed out waiting for the server to complete")
            .expect("error while awaiting tasks");

        endpoints.rebind_all().await;
    }

    #[test]
    fn test_sanitize_src_addr() {
        // ipv4 tests
        assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 4_096))).is_ok());
        assert!(sanitize_src_address(SocketAddr::from(([127, 0, 0, 1], 53))).is_ok());

        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 0))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 0))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 4_096))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([255, 255, 255, 255], 4_096))).is_err());

        // ipv6 tests
        assert!(
            sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 4_096))).is_ok()
        );
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 4_096))).is_ok());

        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 4_096))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))).is_err());
        assert!(
            sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 0))).is_err()
        );
    }

    #[derive(Clone)]
    struct Endpoints {
        udp_addr: SocketAddr,
        tcp_addr: SocketAddr,
        #[cfg(feature = "__tls")]
        rustls_addr: SocketAddr,
        #[cfg(feature = "__https")]
        https_rustls_addr: SocketAddr,
        #[cfg(feature = "__quic")]
        quic_addr: SocketAddr,
        #[cfg(feature = "__h3")]
        h3_addr: SocketAddr,
    }

    impl Endpoints {
        async fn new() -> Self {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__tls")]
            let rustls = TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__https")]
            let https_rustls = TcpListener::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__quic")]
            let quic = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            #[cfg(feature = "__h3")]
            let h3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            Self {
                udp_addr: udp.local_addr().unwrap(),
                tcp_addr: tcp.local_addr().unwrap(),
                #[cfg(feature = "__tls")]
                rustls_addr: rustls.local_addr().unwrap(),
                #[cfg(feature = "__https")]
                https_rustls_addr: https_rustls.local_addr().unwrap(),
                #[cfg(feature = "__quic")]
                quic_addr: quic.local_addr().unwrap(),
                #[cfg(feature = "__h3")]
                h3_addr: h3.local_addr().unwrap(),
            }
        }

        async fn register<T: RequestHandler>(&self, server: &mut Server<T>) {
            server.register_socket(UdpSocket::bind(self.udp_addr).await.unwrap());
            server.register_listener(
                TcpListener::bind(self.tcp_addr).await.unwrap(),
                Duration::from_secs(1),
            );

            #[cfg(feature = "__tls")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_tls_listener(
                        TcpListener::bind(self.rustls_addr).await.unwrap(),
                        Duration::from_secs(30),
                        cert_key,
                    )
                    .unwrap();
            }

            #[cfg(feature = "__https")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_https_listener(
                        TcpListener::bind(self.https_rustls_addr).await.unwrap(),
                        Duration::from_secs(1),
                        cert_key,
                        None,
                        "/dns-query".into(),
                    )
                    .unwrap();
            }

            #[cfg(feature = "__quic")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_quic_listener(
                        UdpSocket::bind(self.quic_addr).await.unwrap(),
                        Duration::from_secs(1),
                        cert_key,
                        None,
                    )
                    .unwrap();
            }

            #[cfg(feature = "__h3")]
            {
                let cert_key = rustls_cert_key();
                server
                    .register_h3_listener(
                        UdpSocket::bind(self.h3_addr).await.unwrap(),
                        Duration::from_secs(1),
                        cert_key,
                        None,
                    )
                    .unwrap();
            }
        }

        async fn rebind_all(&self) {
            UdpSocket::bind(self.udp_addr).await.unwrap();
            TcpListener::bind(self.tcp_addr).await.unwrap();
            #[cfg(feature = "__tls")]
            TcpListener::bind(self.rustls_addr).await.unwrap();
            #[cfg(feature = "__https")]
            TcpListener::bind(self.https_rustls_addr).await.unwrap();
            #[cfg(feature = "__quic")]
            UdpSocket::bind(self.quic_addr).await.unwrap();
            #[cfg(feature = "__h3")]
            UdpSocket::bind(self.h3_addr).await.unwrap();
        }
    }

    #[cfg(feature = "__tls")]
    fn rustls_cert_key() -> Arc<dyn ResolvesServerCert> {
        use rustls::pki_types::pem::PemObject;
        use std::env;

        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
        let cert_chain =
            CertificateDer::pem_file_iter(format!("{server_path}/tests/test-data/cert.pem"))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

        let key = PrivateKeyDer::from_pem_file(format!("{server_path}/tests/test-data/cert.key"))
            .unwrap();

        let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider()).unwrap();
        Arc::new(SingleCertAndKey::from(certified_key))
    }

    #[test]
    fn task_reap_on_empty_joinset() {
        let mut joinset = JoinSet::new();

        // this should return immediately
        reap_tasks(&mut joinset);
    }

    #[tokio::test]
    async fn task_reap_on_nonempty_joinset() {
        let mut joinset = JoinSet::new();
        let t = joinset.spawn(tokio::time::sleep(Duration::from_secs(2)));

        // this should return immediately since no task is ready
        reap_tasks(&mut joinset);
        t.abort();

        // this should also return immediately since the task has been aborted
        reap_tasks(&mut joinset);
    }
}
