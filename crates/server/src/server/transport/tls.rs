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
use tracing::debug;

use super::Transport;
use crate::{
    net::{
        BufDnsStreamHandle, NetError, runtime::DnsTcpListener, tcp::TcpStream, tls::TlsListener,
        tls::tls_config, xfer::Protocol,
    },
    server::{
        ServerContext,
        request_handler::RequestHandler,
        timeout_stream::TimeoutStream,
        utils::{is_unrecoverable_socket_error, reap_tasks},
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
            Arc::new(tls_config::server_tcp(b"dot", server_cert_resolver)?),
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
    async fn run<H: RequestHandler>(self, cx: Arc<ServerContext<H>>) -> Result<(), NetError> {
        handle_tls(
            self.listener,
            self.handshake_timeout,
            self.stream_timeout,
            cx,
        )
        .await
    }
}

#[cfg(feature = "__tls")]
async fn handle_tls<L: DnsTcpListener>(
    mut listener: TlsListener<L>,
    handshake_timeout: Option<Duration>,
    stream_timeout: Option<Duration>,
    cx: Arc<ServerContext<impl RequestHandler>>,
) -> Result<(), NetError> {
    let mut inner_join_set = JoinSet::new();
    loop {
        let Some(result) = cx
            .shutdown
            .run_until_cancelled(listener.accept(handshake_timeout))
            .await
        else {
            // A graceful shutdown was initiated. Break out of the loop.
            break;
        };
        let accepted = match result {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, "error receiving TLS tcp_stream error");
                if is_unrecoverable_socket_error(&error) {
                    break;
                }
                continue;
            }
        };

        let cx = cx.clone();
        inner_join_set.spawn(async move {
            let src_addr = accepted.src_addr;
            let (stream_handle, outbound_messages) = BufDnsStreamHandle::new(src_addr);
            let buf_stream = TcpStream::from_stream_with_receiver(
                accepted.connection,
                src_addr,
                outbound_messages,
            );
            let mut timeout_stream = TimeoutStream::new(buf_stream, stream_timeout);
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
        Err(NetError::from("unexpected close of socket"))
    }
}
