// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{sync::Arc, task::Context, time::Duration};

use super::Transport;
use crate::{
    net::{
        NetError,
        h3::{BodyStream, H3Connection, H3Listener},
        http::{self, Version, fetch_body},
        quic::IntoQuicSocket,
        runtime::Accepted,
        tls::tls_config,
        xfer::Protocol,
    },
    proto::rr::Record,
    server::{
        ResponseInfo, ServerContext,
        request_handler::RequestHandler,
        response_handler::ResponseHandler,
        utils::{self, reap_tasks},
    },
    zone_handler::MessageResponse,
};
use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use rustls::{ServerConfig, server::ResolvesServerCert};
use tokio::task::JoinSet;
use tracing::{debug, warn};

/// Builder and transport implementation for DNS-over-HTTP/3 (DoH3).
///
/// Wraps an already-bound UDP socket and a TLS configuration to accept HTTP/3 connections.
#[derive(Debug)]
pub struct H3 {
    listener: H3Listener,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
}

impl H3 {
    /// Constructs a new HTTP/3 transport with the provided [`ServerConfig`].
    ///
    /// The `socket` must be already bound to the desired local address, and the configuration
    /// must enable the H3 ALPN protocol. Default timeouts are `None`.
    ///
    /// Initializes the QUIC endpoint immediately and requires a Tokio runtime.
    /// Returns errors from TLS configuration conversion, socket conversion, or endpoint creation.
    pub fn with_tls_config(
        socket: impl IntoQuicSocket,
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self, NetError> {
        Ok(Self {
            listener: H3Listener::with_socket_and_tls_config(socket, tls_config)?,
            handshake_timeout: None,
            idle_timeout: None,
            request_timeout: None,
        })
    }

    /// Constructs a new HTTP/3 transport with a certificate resolver.
    ///
    /// A default TLS 1.3 configuration with ALPN `h3` and the QUIC endpoint are constructed
    /// immediately. Requires a Tokio runtime and returns listener initialization errors.
    pub fn new(
        socket: impl IntoQuicSocket,
        cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        Self::with_tls_config(
            socket,
            Arc::new(tls_config::server_quic(b"h3", cert_resolver)),
        )
    }

    /// Sets the timeout for the QUIC handshake and HTTP/3 initialization together.
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

    /// Sets the timeout before closing an idle connection.
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
}

impl Transport for H3 {
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_h3_with_server(
            self.listener,
            self.handshake_timeout,
            self.idle_timeout,
            self.request_timeout,
            cx,
        )
        .await
    }
}

async fn handle_h3_with_server(
    mut server: H3Listener,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let mut inner_join_set = JoinSet::new();
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(server.accept(handshake_timeout));
        let Some(connection_opt) = future.await else {
            break; // A graceful shutdown was initiated. Break out of the loop.
        };
        let Some(connection_result) = connection_opt else {
            break; // Connection is closed.
        };
        let connection = match connection_result {
            Ok(connection) => connection,
            Err(error) => {
                debug!(%error, "error accepting incoming h3 connection");
                continue;
            }
        };

        let cx = cx.clone();
        inner_join_set.spawn(async move {
            let src_addr = connection.src_addr;
            debug!("starting h3 stream request from: {src_addr}");

            let result = h3_handler(connection, idle_timeout, request_timeout, cx).await;

            if let Err(error) = result {
                warn!(%error, %src_addr, "h3 stream processing failed")
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    Ok(())
}

async fn h3_handler(
    mut accepted: Accepted<H3Connection>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let src_addr = accepted.src_addr;
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound requests sent over the connection.
    loop {
        let future = cx.shutdown.run_until_cancelled(utils::optional_timeout(
            idle_timeout,
            accepted.connection.accept(),
        ));
        let Some(timeout_result) = future.await else {
            break; // A graceful shutdown was initiated.
        };
        let Ok(accept_result) = timeout_result else {
            break; // Timeout elapsed while waiting for a request.
        };
        let request_resolver_opt = match accept_result {
            Ok(request_resolver_opt) => request_resolver_opt,
            Err(error) => {
                warn!(%src_addr, %error, "error accepting request");
                return Err(error);
            }
        };
        let Some(request_resolver) = request_resolver_opt else {
            break; // The connection is closed.
        };

        let cx = cx.clone();
        tokio::spawn(async move {
            let mut stream = match request_resolver.resolve_request().await {
                Ok((_request, stream)) => stream,
                Err(error) => {
                    warn!(%error, "error receiving request headers");
                    return;
                }
            };

            let fetch_future = fetch_body(
                BodyStream::from(|cx: &mut Context<'_>| stream.poll_recv_data(cx)),
                None,
            );
            let Ok(request_res) = utils::optional_timeout(request_timeout, fetch_future).await
            else {
                return; //Timeout while reading request.
            };
            let request = match request_res {
                Ok(bytes_mut) => bytes_mut.freeze(),
                Err(error) => {
                    warn!(%error, "error receiving request body");
                    return;
                }
            };

            debug!(
                %src_addr,
                bytes = request.remaining(),
                ?request,
                "Received request body"
            );

            cx.handle_request(request, src_addr, Protocol::H3, H3ResponseHandle(stream))
                .await
        });

        max_requests -= 1;
        if max_requests == 0 {
            warn!("exceeded request count, shutting down h3 conn: {src_addr}");
            accepted.connection.shutdown().await?;
            break;
        }
        // we'll continue handling requests from here.
    }

    Ok(())
}

struct H3ResponseHandle(RequestStream<BidiStream<Bytes>, Bytes>);

#[async_trait::async_trait]
impl ResponseHandler for H3ResponseHandle {
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
        let (info, bytes) = response.encode(Protocol::H3)?;
        let bytes = Bytes::from(bytes);
        let response = http::response(Version::Http3, bytes.len())?;

        debug!("sending response: {:#?}", response);
        let stream = &mut self.0;
        stream.send_response(response).await?;
        stream.send_data(bytes).await?;
        stream.finish().await?;

        Ok(info)
    }
}
