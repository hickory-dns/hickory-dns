// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use h2::server::{self, SendResponse};
use rustls::{ServerConfig, server::ResolvesServerCert};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use super::Transport;
use crate::net::sanitize_src_address;
use crate::{
    net::{
        NetError,
        h2::message_from,
        http::{self, Version},
        runtime::{DnsTcpListener, iocompat::AsyncIoStdAsTokio},
        tls::tls_config,
        xfer::Protocol,
    },
    proto::rr::Record,
    server::{
        ResponseInfo, ServerContext, is_unrecoverable_socket_error, optional_timeout, reap_tasks,
        request_handler::RequestHandler, response_handler::ResponseHandler,
    },
    zone_handler::MessageResponse,
};

/// Builder and transport implementation for DNS-over-HTTPS (DoH / HTTP/2).
///
/// Wraps an already-bound TCP listener and a TLS configuration to accept HTTP/2 DNS queries.
#[derive(Debug)]
pub struct H2<L: DnsTcpListener> {
    listener: L,
    tls_config: Arc<ServerConfig>,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<String>,
    http_endpoint: String,
}

impl<L: DnsTcpListener> H2<L> {
    /// Constructs a new HTTPS transport with the provided [`ServerConfig`].
    ///
    /// The `listener` must be already bound to the desired local address.
    /// Default HTTP endpoint is `/dns-query`, and timeouts are `None`.
    pub fn with_tls_config(listener: L, tls_config: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            tls_config,
            handshake_timeout: None,
            idle_timeout: None,
            request_timeout: None,
            dns_hostname: None,
            http_endpoint: http::DEFAULT_DNS_QUERY_PATH.to_string(),
        }
    }

    /// Constructs a new HTTPS transport with a certificate resolver.
    ///
    /// A default configuration using the safe default protocol versions and ALPN `h2` is
    /// constructed immediately.
    pub fn new(
        listener: L,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        Ok(Self::with_tls_config(
            listener,
            Arc::new(tls_config::server_tcp(b"h2", server_cert_resolver)?),
        ))
    }

    /// Sets the timeout duration for performing TLS handshakes.
    pub fn handshake_timeout(self, handshake_timeout: Duration) -> Self {
        self.maybe_handshake_timeout(Some(handshake_timeout))
    }

    /// Sets the handshake timeout; pass `None` to disable it.
    pub fn maybe_handshake_timeout(self, handshake_timeout: Option<Duration>) -> Self {
        Self {
            handshake_timeout,
            ..self
        }
    }

    /// Sets the timeout before closing an idle HTTP/2 connection.
    pub fn idle_timeout(self, idle_timeout: Duration) -> Self {
        self.maybe_idle_timeout(Some(idle_timeout))
    }

    /// Sets the idle timeout; pass `None` to disable it.
    pub fn maybe_idle_timeout(self, idle_timeout: Option<Duration>) -> Self {
        Self {
            idle_timeout,
            ..self
        }
    }

    /// Sets the timeout for receiving a complete request over a stream.
    pub fn request_timeout(self, request_timeout: Duration) -> Self {
        self.maybe_request_timeout(Some(request_timeout))
    }

    /// Sets the request timeout; pass `None` to disable it.
    pub fn maybe_request_timeout(self, request_timeout: Option<Duration>) -> Self {
        Self {
            request_timeout,
            ..self
        }
    }

    /// Sets the DNS hostname for this HTTPS server.
    pub fn dns_hostname(self, dns_hostname: String) -> Self {
        Self {
            dns_hostname: Some(dns_hostname),
            ..self
        }
    }

    /// Optionally sets the DNS hostname for this HTTPS server.
    pub fn maybe_dns_hostname(self, dns_hostname: Option<String>) -> Self {
        Self {
            dns_hostname,
            ..self
        }
    }

    /// Sets the HTTP query endpoint path (defaults to `/dns-query`).
    pub fn http_endpoint(self, http_endpoint: String) -> Self {
        Self {
            http_endpoint,
            ..self
        }
    }
}

impl<L: DnsTcpListener> Transport for H2<L> {
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_h2_with_acceptor(
            self.listener,
            self.handshake_timeout,
            self.idle_timeout,
            self.request_timeout,
            TlsAcceptor::from(self.tls_config),
            self.dns_hostname,
            self.http_endpoint,
            cx,
        )
        .await
    }
}

/// handle h2 using a specific TlsAcceptor.
#[allow(clippy::too_many_arguments)]
async fn handle_h2_with_acceptor<L: DnsTcpListener>(
    mut listener: L,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    tls_acceptor: TlsAcceptor,
    dns_hostname: Option<String>,
    http_endpoint: String,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let dns_hostname: Option<Arc<str>> = dns_hostname.map(|n| n.into());
    let http_endpoint: Arc<str> = Arc::from(http_endpoint);

    let mut inner_join_set = JoinSet::new();
    loop {
        let shutdown = &cx.shutdown;
        let accept = futures_util::future::poll_fn(|cx| listener.poll_accept(cx));
        let Some(result) = shutdown.run_until_cancelled(accept).await else {
            // A graceful shutdown was initiated. Break out of the loop.
            break;
        };
        let (tcp_stream, src_addr) = match result {
            Ok(accepted) => (accepted.connection, accepted.src_addr),
            Err(error) => {
                debug!(%error, "error receiving HTTPS tcp_stream error");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
        };

        // verify that the src address is safe for responses
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(%error, %src_addr, "address can not be responded to");
            continue;
        }

        let cx = cx.clone();
        let tls_acceptor = tls_acceptor.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        inner_join_set.spawn(async move {
            debug!("starting HTTPS request from: {src_addr}");

            let Ok(tls_stream) = optional_timeout(
                handshake_timeout,
                tls_acceptor.accept(AsyncIoStdAsTokio(tcp_stream)),
            )
            .await
            else {
                warn!("https timeout expired during handshake");
                return;
            };

            let tls_stream = match tls_stream {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    debug!("https handshake src: {src_addr} error: {e}");
                    return;
                }
            };
            debug!("accepted HTTPS request from: {src_addr}");

            h2_handler(
                tls_stream,
                src_addr,
                idle_timeout,
                request_timeout,
                dns_hostname,
                http_endpoint,
                cx,
            )
            .await;
        });

        reap_tasks(&mut inner_join_set);
    }

    if cx.shutdown.is_cancelled() {
        Ok(())
    } else {
        Err(NetError::from("unexpected close of socket"))
    }
}

async fn h2_handler(
    io: impl AsyncRead + AsyncWrite + Unpin,
    src_addr: SocketAddr,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) {
    let dns_hostname = dns_hostname.clone();
    let http_endpoint = http_endpoint.clone();

    // Start the HTTP/2.0 connection handshake
    let mut h2 = match server::handshake(io).await {
        Ok(h2) => h2,
        Err(err) => {
            warn!("handshake error from {}: {}", src_addr, err);
            return;
        }
    };

    // Accept all inbound HTTP/2.0 streams sent over the
    // connection.
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(optional_timeout(idle_timeout, h2.accept()));
        let Some(timeout_result) = future.await else {
            break; // A graceful shutdown was initiated.
        };
        let Ok(accept_option) = timeout_result else {
            break; // Timeout elapsed while waiting for a request.
        };
        let Some(result) = accept_option else {
            break; // The connection is closed.
        };
        let (request, respond) = match result {
            Ok(pair) => pair,
            Err(error) => {
                warn!("error accepting request {}: {}", src_addr, error);
                break;
            }
        };

        debug!("Received request: {:#?}", request);
        let cx = cx.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        tokio::spawn(async move {
            let message_future = message_from(dns_hostname, http_endpoint, request);
            let Ok(result) = optional_timeout(request_timeout, message_future).await else {
                return; // Timeout while reading request.
            };
            let body = match result {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!("error while handling request from {}: {}", src_addr, err);
                    return;
                }
            };

            cx.handle_request(
                body.freeze(),
                src_addr,
                Protocol::Https,
                H2ResponseHandle(respond),
            )
            .await
        });

        // we'll continue handling requests from here.
    }
}

struct H2ResponseHandle(SendResponse<Bytes>);

#[async_trait::async_trait]
impl ResponseHandler for H2ResponseHandle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let (info, bytes) = response.encode(Protocol::Https)?;
        let bytes = Bytes::from(bytes);
        let response = http::response(Version::Http2, bytes.len())?;

        debug!("sending response: {:#?}", response);
        let mut stream = self.0.send_response(response, false)?;
        stream.send_data(bytes, true)?;

        Ok(info)
    }
}
