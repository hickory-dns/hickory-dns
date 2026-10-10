// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use rustls::{ServerConfig, server::ResolvesServerCert};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Transport;
use crate::{
    net::{
        BufDnsStreamHandle, NetError,
        runtime::{Accepted, DnsTcpListener},
        tcp::TcpStream,
        tls::{TlsListener, TlsServerStream, alpn, tls_config},
        xfer::Protocol,
    },
    server::{
        ServerContext, request_handler::RequestHandler, timeout_stream::TimeoutStream,
        utils::is_unrecoverable_socket_error,
    },
};

/// Builder and transport implementation for DNS-over-TLS (DoT).
///
/// Wraps an already-bound TCP listener and a TLS configuration to accept encrypted DNS queries.
#[derive(Debug)]
pub struct Tls<L: DnsTcpListener> {
    listener: TlsListener<L>,
    handshake_timeout: Option<Duration>,
    stream_timeout: Option<Duration>,
}

impl<L: DnsTcpListener> Tls<L> {
    /// Constructs a new TLS transport with the provided [`ServerConfig`].
    ///
    /// The `listener` must be already bound to the desired local address.
    /// Default handshake and stream timeouts are `None`.
    pub fn with_tls_config(listener: L, tls_config: Arc<ServerConfig>) -> Self {
        Self {
            listener: TlsListener::new(listener, tls_config),
            handshake_timeout: None,
            stream_timeout: None,
        }
    }

    /// Constructs a new TLS transport with a certificate resolver.
    ///
    /// A default configuration using the safe default protocol versions and ALPN `dot` is
    /// constructed immediately.
    pub fn new(
        listener: L,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        Ok(Self::with_tls_config(
            listener,
            Arc::new(tls_config::server_tcp(alpn::DOT, server_cert_resolver)?),
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

    /// Sets the timeout duration for incoming request streams.
    pub fn stream_timeout(self, stream_timeout: Duration) -> Self {
        self.maybe_stream_timeout(Some(stream_timeout))
    }

    /// Sets the stream timeout; pass `None` to disable it.
    pub fn maybe_stream_timeout(self, stream_timeout: Option<Duration>) -> Self {
        Self {
            stream_timeout,
            ..self
        }
    }
}

impl<L: DnsTcpListener> Transport for Tls<L> {
    async fn accept<H: RequestHandler>(
        &mut self,
        cx: Arc<ServerContext<H>>,
        tasks: &mut JoinSet<()>,
    ) -> Result<bool, NetError> {
        let accepted = match self.listener.accept(self.handshake_timeout).await {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, protocol = %Protocol::Tls, "error receiving transport input");
                return Ok(!is_unrecoverable_socket_error(&error));
            }
        };

        let stream_timeout = self.stream_timeout;
        tasks.spawn(async move {
            let src_addr = accepted.src_addr;
            debug!(%src_addr, protocol = %Protocol::Tls, "starting request processing");

            let result = Self::handle(accepted, stream_timeout, cx).await;

            if let Err(error) = result {
                warn!(%src_addr, %error, protocol = %Protocol::Tls, "request processing failed");
            }
        });

        Ok(true)
    }
}

impl<L: DnsTcpListener> Tls<L> {
    async fn handle(
        accepted: Accepted<TlsServerStream<L::Stream>>,
        stream_timeout: Option<Duration>,
        cx: Arc<ServerContext<impl RequestHandler>>,
    ) -> Result<(), NetError> {
        let src_addr = accepted.src_addr;
        let (stream_handle, outbound_messages) = BufDnsStreamHandle::new(src_addr);
        let buf_stream =
            TcpStream::from_stream_with_receiver(accepted.connection, src_addr, outbound_messages);
        let mut timeout_stream = TimeoutStream::new(buf_stream, stream_timeout);
        while let Some(message) = timeout_stream.next().await {
            cx.handle_raw_request(message?, Protocol::Tls, stream_handle.clone())
                .await;
        }

        Ok(())
    }
}
