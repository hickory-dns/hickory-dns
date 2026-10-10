// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use h2::server::SendResponse;
use rustls::{ServerConfig, server::ResolvesServerCert};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Transport;
use crate::{
    net::{
        NetError,
        h2::{H2Connection, H2Listener, message_from},
        http::{self, Version},
        runtime::{DnsTcpListener, DnsTcpStream},
        tls::{alpn, tls_config},
        xfer::Protocol,
    },
    proto::rr::Record,
    server::{
        ResponseInfo, ServerContext,
        request_handler::RequestHandler,
        response_handler::ResponseHandler,
        utils::{self, is_unrecoverable_socket_error},
    },
    zone_handler::MessageResponse,
};

/// Builder and transport implementation for DNS-over-HTTPS (DoH / HTTP/2).
///
/// Wraps an already-bound TCP listener and a TLS configuration to accept HTTP/2 DNS queries.
#[derive(Debug)]
pub struct H2<L: DnsTcpListener> {
    listener: H2Listener<L>,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
}

impl<L: DnsTcpListener> H2<L> {
    /// Constructs a new HTTPS transport with the provided [`ServerConfig`].
    ///
    /// The `listener` must be already bound to the desired local address.
    /// Default HTTP endpoint is `/dns-query`, and timeouts are `None`.
    pub fn with_tls_config(listener: L, tls_config: Arc<ServerConfig>) -> Self {
        Self {
            listener: H2Listener::new(listener, tls_config),
            handshake_timeout: None,
            idle_timeout: None,
            request_timeout: None,
            dns_hostname: None,
            http_endpoint: Arc::from(http::DEFAULT_DNS_QUERY_PATH),
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
            Arc::new(tls_config::server_tcp(alpn::H2, server_cert_resolver)?),
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
            dns_hostname: Some(dns_hostname.into()),
            ..self
        }
    }

    /// Optionally sets the DNS hostname for this HTTPS server.
    pub fn maybe_dns_hostname(self, dns_hostname: Option<String>) -> Self {
        Self {
            dns_hostname: dns_hostname.map(Arc::from),
            ..self
        }
    }

    /// Sets the HTTP query endpoint path (defaults to `/dns-query`).
    pub fn http_endpoint(self, http_endpoint: String) -> Self {
        Self {
            http_endpoint: http_endpoint.into(),
            ..self
        }
    }
}

impl<L: DnsTcpListener> Transport for H2<L> {
    async fn accept<H: RequestHandler>(
        &mut self,
        cx: Arc<ServerContext<H>>,
        tasks: &mut JoinSet<()>,
    ) -> Result<bool, NetError> {
        let accepted = match self.listener.accept(self.handshake_timeout).await {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, protocol = %Protocol::Https, "error receiving transport input");
                return Ok(!is_unrecoverable_socket_error(&error));
            }
        };

        let dns_hostname = self.dns_hostname.clone();
        let http_endpoint = self.http_endpoint.clone();
        let idle_timeout = self.idle_timeout;
        let request_timeout = self.request_timeout;
        tasks.spawn(async move {
            let src_addr = accepted.src_addr();
            debug!(%src_addr, protocol = %Protocol::Https, "starting request processing");

            let result = Self::handle(
                accepted,
                idle_timeout,
                request_timeout,
                dns_hostname,
                http_endpoint,
                cx,
            )
            .await;

            if let Err(error) = result {
                warn!(%src_addr, %error, protocol = %Protocol::Https, "request processing failed");
            }
        });

        Ok(true)
    }
}

impl<L: DnsTcpListener> H2<L> {
    async fn handle(
        mut connection: H2Connection<impl DnsTcpStream>,
        idle_timeout: Option<Duration>,
        request_timeout: Option<Duration>,
        dns_hostname: Option<Arc<str>>,
        http_endpoint: Arc<str>,
        cx: Arc<ServerContext<impl RequestHandler>>,
    ) -> Result<(), NetError> {
        let src_addr = connection.src_addr();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();

        // Accept all inbound HTTP/2.0 streams sent over the
        // connection.
        loop {
            let future = cx
                .shutdown
                .run_until_cancelled(utils::timeout(idle_timeout, connection.accept()));
            let Some(timeout_result) = future.await else {
                break; // A graceful shutdown was initiated.
            };
            let Ok(accept_option) = timeout_result else {
                break; // Timeout elapsed while waiting for a request.
            };
            let Some(result) = accept_option else {
                break; // The connection is closed.
            };
            let (request, respond) = result?;

            debug!("Received request: {:#?}", request);
            let cx = cx.clone();
            let dns_hostname = dns_hostname.clone();
            let http_endpoint = http_endpoint.clone();
            tokio::spawn(async move {
                let message_future = message_from(dns_hostname, http_endpoint, request);
                let Ok(result) = utils::timeout(request_timeout, message_future).await else {
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

        Ok(())
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
