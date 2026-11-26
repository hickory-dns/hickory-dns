// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::future::poll_fn;
use h2::server;
use rustls::ServerConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use super::{
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, SealedTransport,
    ServerContext, is_unrecoverable_socket_error, optional_timeout, reap_tasks,
    request_handler::RequestHandler, sanitize_src_address,
};
use crate::net::{
    NetError,
    http::{DEFAULT_QUERY_PATH, Version},
    runtime::{Accepted, DnsTcpListener, iocompat::AsyncIoStdAsTokio},
    xfer::Protocol,
};

/// Builder and transport implementation for DNS-over-HTTPS (DoH) using HTTP/2.
///
/// Wraps an already-bound TCP listener and a TLS configuration to accept HTTP/2 DNS queries.
///
/// To make the server more resilient to DOS issues, timeouts are enabled by default. Care
/// should be taken to not make them too low depending on use cases.
pub struct H2<L: DnsTcpListener> {
    listener: L,
    tls_config: Arc<ServerConfig>,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<String>,
    query_path: String,
}

impl<L: DnsTcpListener> H2<L> {
    /// Constructs a new HTTP/2 transport with the provided [`ServerConfig`].
    ///
    /// The `listener` must already be bound to a local address, and `tls_config` should enable the
    /// `h2` ALPN protocol. Timeouts default to [`DEFAULT_HANDSHAKE_TIMEOUT`],
    /// [`DEFAULT_IDLE_TIMEOUT`], and [`DEFAULT_REQUEST_TIMEOUT`], and the query path defaults to
    /// [`DEFAULT_QUERY_PATH`].
    pub fn new(listener: L, tls_config: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            tls_config,
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            dns_hostname: None,
            query_path: DEFAULT_QUERY_PATH.to_owned(),
        }
    }

    /// Sets the timeout for completing a TLS handshake; pass `None` to disable it.
    pub fn handshake_timeout(self, handshake_timeout: Option<Duration>) -> Self {
        Self {
            handshake_timeout,
            ..self
        }
    }

    /// Sets the timeout before closing an idle connection; pass `None` to disable it.
    pub fn idle_timeout(self, idle_timeout: Option<Duration>) -> Self {
        Self {
            idle_timeout,
            ..self
        }
    }

    /// Sets the timeout for receiving a complete request on a stream; pass `None` to disable it.
    pub fn request_timeout(self, request_timeout: Option<Duration>) -> Self {
        Self {
            request_timeout,
            ..self
        }
    }

    /// Sets the expected DNS hostname for HTTPS requests; pass `None` to disable it.
    pub fn dns_hostname(self, dns_hostname: Option<String>) -> Self {
        Self {
            dns_hostname,
            ..self
        }
    }

    /// Sets the HTTP query path used to serve DNS queries.
    pub fn query_path(self, query_path: String) -> Self {
        Self { query_path, ..self }
    }
}

impl<L: DnsTcpListener> SealedTransport for H2<L> {
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        let Self {
            mut listener,
            tls_config,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            dns_hostname,
            query_path,
        } = self;

        let tls_acceptor = TlsAcceptor::from(tls_config);
        let dns_hostname: Option<Arc<str>> = dns_hostname.map(|n| n.into());
        let query_path: Arc<str> = Arc::from(query_path);

        let mut inner_join_set = JoinSet::new();
        loop {
            let shutdown = &cx.shutdown;
            let accept = poll_fn(|cx| listener.poll_accept(cx));
            let Some(result) = shutdown.run_until_cancelled(accept).await else {
                // A graceful shutdown was initiated. Break out of the loop.
                break;
            };
            let (connection, src_addr) = match result {
                Ok(Accepted {
                    connection,
                    src_addr,
                }) => (connection, src_addr),
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
            let query_path = query_path.clone();
            inner_join_set.spawn(async move {
                debug!("starting HTTPS request from: {src_addr}");

                let Ok(tls_stream) = optional_timeout(
                    handshake_timeout,
                    tls_acceptor.accept(AsyncIoStdAsTokio(connection)),
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
                    query_path,
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
}

impl<L: DnsTcpListener + fmt::Debug> fmt::Debug for H2<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            listener,
            tls_config: _,
            handshake_timeout,
            idle_timeout,
            request_timeout,
            dns_hostname,
            query_path,
        } = self;

        f.debug_struct("H2")
            .field("listener", listener)
            .field("handshake_timeout", handshake_timeout)
            .field("idle_timeout", idle_timeout)
            .field("request_timeout", request_timeout)
            .field("dns_hostname", dns_hostname)
            .field("query_path", query_path)
            .finish_non_exhaustive()
    }
}

pub(crate) async fn h2_handler(
    io: impl AsyncRead + AsyncWrite + Unpin,
    src_addr: SocketAddr,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<Arc<str>>,
    query_path: Arc<str>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) {
    let dns_hostname = dns_hostname.clone();
    let query_path = query_path.clone();

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
        let (request, mut respond) = match result {
            Ok(pair) => pair,
            Err(error) => {
                warn!("error accepting request {}: {}", src_addr, error);
                break;
            }
        };

        debug!("Received request: {:#?}", request);
        let cx = cx.clone();
        let dns_hostname = dns_hostname.clone();
        let query_path = query_path.clone();
        tokio::spawn(async move {
            let message_future = Version::Http2.message_from(request, query_path, dns_hostname);
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

            let Some((info, reporter)) = cx
                .handle_request(body.freeze(), src_addr, Protocol::Https)
                .await
            else {
                return;
            };

            let bytes = Bytes::from(info.bytes);
            let response = match Version::Http2.response(bytes.len(), info.cache_ttl) {
                Ok(response) => response,
                Err(error) => {
                    warn!(%error, "failed to build response");
                    return;
                }
            };

            debug!("sending response: {:#?}", response);
            let mut stream = match respond.send_response(response, false) {
                Ok(stream) => stream,
                Err(error) => {
                    warn!(%error, "failed to send response");
                    return;
                }
            };

            if let Err(error) = stream.send_data(bytes, true) {
                warn!(%error, "failed to send response");
                return;
            }

            reporter.report(&info.header);
        });

        // we'll continue handling requests from here.
    }
}
