// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use super::Transport;
use crate::net::sanitize_src_address;
use crate::{
    net::{
        NetError,
        quic::{IntoQuicSocket, QuicServer, QuicStream, QuicStreams},
        tls::tls_config,
        xfer::Protocol,
    },
    proto::rr::Record,
    server::{
        ResponseInfo, ServerContext, optional_timeout, reap_tasks, request_handler::RequestHandler,
        response_handler::ResponseHandler,
    },
    zone_handler::MessageResponse,
};
use bytes::Bytes;
use rustls::{ServerConfig, server::ResolvesServerCert};
use tokio::task::JoinSet;
use tracing::{debug, warn};

/// Builder and transport implementation for DNS-over-QUIC (DoQ).
///
/// Wraps an already-bound UDP socket and a TLS configuration to accept QUIC connections.
#[derive(Debug)]
pub struct Quic {
    listener: QuicServer,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
}

impl Quic {
    /// Constructs a new QUIC transport with the provided [`ServerConfig`].
    ///
    /// The `socket` must be already bound to the desired local address, and the configuration
    /// must enable the DoQ ALPN protocol. Default timeouts are `None`.
    ///
    /// Initializes the QUIC endpoint immediately and requires a Tokio runtime.
    /// Returns errors from TLS configuration conversion, socket conversion, or endpoint creation.
    pub fn with_tls_config(
        socket: impl IntoQuicSocket,
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self, NetError> {
        Ok(Self {
            listener: QuicServer::with_socket_and_tls_config(socket, tls_config)?,
            handshake_timeout: None,
            idle_timeout: None,
            request_timeout: None,
        })
    }

    /// Constructs a new QUIC transport with a certificate resolver.
    ///
    /// A default TLS 1.3 configuration with ALPN `doq` and the QUIC endpoint are constructed
    /// immediately. Requires a Tokio runtime and returns listener initialization errors.
    pub fn new(
        socket: impl IntoQuicSocket,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        Self::with_tls_config(
            socket,
            Arc::new(tls_config::server_quic(b"doq", server_cert_resolver)),
        )
    }

    /// Sets the timeout duration for performing QUIC handshakes.
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

    /// Sets the timeout before closing an idle QUIC connection.
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

impl Transport for Quic {
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_quic_with_server(
            self.listener,
            self.handshake_timeout,
            self.idle_timeout,
            self.request_timeout,
            cx,
        )
        .await
    }
}

async fn handle_quic_with_server(
    mut server: QuicServer,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let mut inner_join_set = JoinSet::new();
    loop {
        let future = cx.shutdown.run_until_cancelled(server.next());
        let Some(incoming_opt) = future.await else {
            break; // A graceful shutdown was initiated. Break out of the loop.
        };
        let Some(incoming) = incoming_opt else {
            break; // Connection is closed.
        };

        // If the remote address isn't validated, send a retry packet to request that the client try
        // connecting again, with address validation.
        if !incoming.remote_address_validated() {
            if let Err(error) = incoming.retry() {
                warn!(%error, "could not send retry packet");
            }
            continue;
        }

        // Verify that the source address is safe for responses.
        let src_addr = incoming.remote_address();
        if let Err(error) = sanitize_src_address(src_addr) {
            warn!(
                %error, %src_addr,
                "address can not be responded to",
            );
            continue;
        }

        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                debug!(%error, "error accepting incoming quic connection");
                continue;
            }
        };

        let cx = cx.clone();
        inner_join_set.spawn(async move {
            let handshake_future = QuicStreams::new(connecting);
            let Ok(streams_result) = optional_timeout(handshake_timeout, handshake_future).await
            else {
                warn!("quic timeout expired during handshake");
                return;
            };
            let streams = match streams_result {
                Ok(streams) => streams,
                Err(error) => {
                    debug!(%error, "error completing incoming quic connection");
                    return;
                }
            };

            debug!("starting quic stream request from: {src_addr}");

            let result = quic_handler(streams, src_addr, idle_timeout, request_timeout, cx).await;

            if let Err(error) = result {
                warn!(%error, %src_addr, "quic stream processing failed")
            }
        });

        reap_tasks(&mut inner_join_set);
    }

    Ok(())
}

async fn quic_handler(
    mut quic_streams: QuicStreams,
    src_addr: SocketAddr,
    idle_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    // TODO: we should make this configurable
    let mut max_requests = 100u32;

    // Accept all inbound quic streams sent over the connection.
    loop {
        let future = cx
            .shutdown
            .run_until_cancelled(optional_timeout(idle_timeout, quic_streams.next()));
        let Some(timeout_result) = future.await else {
            break; // A graceful shutdown was initiated.
        };
        let Ok(stream_option) = timeout_result else {
            break; // Timeout elapsed while waiting for a request.
        };
        let Some(result) = stream_option else {
            break;
        };
        let mut request_stream = match result {
            Ok(next_request) => next_request,
            Err(err) => {
                warn!("error accepting request {}: {}", src_addr, err);
                return Err(err);
            }
        };

        let cx = cx.clone();
        tokio::spawn(async move {
            let Ok(request_res) =
                optional_timeout(request_timeout, request_stream.receive_bytes()).await
            else {
                return; // Timeout while reading body.
            };
            let request = match request_res {
                Ok(bytes_mut) => bytes_mut.freeze(),
                Err(error) => {
                    warn!(%error, %src_addr, "reading quic request failed");
                    return;
                }
            };

            debug!(
                "Received bytes {} from {src_addr} {request:?}",
                request.len()
            );

            cx.handle_request(
                request,
                src_addr,
                Protocol::Quic,
                QuicResponseHandle(request_stream),
            )
            .await;
        });

        max_requests -= 1;
        if max_requests == 0 {
            warn!("exceeded request count, shutting down quic conn: {src_addr}");
            break;
        }
        // we'll continue handling requests from here.
    }

    Ok(())
}

struct QuicResponseHandle(QuicStream);

#[async_trait::async_trait]
impl ResponseHandler for QuicResponseHandle {
    // TODO: rethink this entire interface
    async fn send_response<'a>(
        &mut self,
        mut response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // The id should always be 0 in DoQ
        response.metadata_mut().id = 0;
        let (info, bytes) = response.encode(Protocol::Quic)?;
        let bytes = Bytes::from(bytes);

        debug!("sending quic response: {}", bytes.len());
        let stream = &mut self.0;
        stream.send_bytes(bytes).await?;
        stream.finish().await?;

        Ok(info)
    }
}
