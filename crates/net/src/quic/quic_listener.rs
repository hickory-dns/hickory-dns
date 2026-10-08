// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::net::SocketAddr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::{
    IntoQuicSocket, quic_config,
    quic_endpoint::{QuicEndpoint, QuicHandshake},
    quic_stream::QuicStream,
};
use crate::tls::tls_config;
use crate::{error::NetError, runtime::Accepted};
use quinn::{Connecting, Connection};
use rustls::server::ResolvesServerCert;
use rustls::server::ServerConfig as TlsServerConfig;
use tokio::net::UdpSocket;

/// An established QUIC connection that accepts bidirectional streams.
pub struct QuicConnection {
    connection: Connection,
}

impl QuicConnection {
    /// Get the next bidirectional stream from the client
    pub async fn accept(&mut self) -> Result<QuicStream, NetError> {
        match self.connection.accept_bi().await {
            Ok((send, receive)) => Ok(QuicStream::new(send, receive)),
            Err(e) => Err(NetError::from(e)),
        }
    }
}

impl QuicHandshake for QuicConnection {
    async fn handshake(connecting: Connecting) -> Result<Self, NetError> {
        Ok(Self {
            connection: connecting.await?,
        })
    }
}

/// A listener for established DNS-over-QUIC connections.
#[derive(Debug)]
pub struct QuicListener {
    endpoint: QuicEndpoint<QuicConnection>,
}

impl QuicListener {
    /// Binds a UDP socket and constructs a listener with a default TLS configuration.
    pub async fn new(
        name_server: SocketAddr,
        cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        Self::with_socket(UdpSocket::bind(name_server).await?, cert_resolver)
    }

    /// Constructs a listener with an existing socket and a default TLS configuration.
    pub fn with_socket(
        socket: impl IntoQuicSocket,
        cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        let config = tls_config::server_quic(b"doq", cert_resolver);
        Self::with_socket_and_tls_config(socket, Arc::new(config))
    }

    /// Constructs a listener with an existing socket and a custom TLS configuration.
    ///
    /// The caller must ensure the `TlsServerConfig` has the appropriate DoQ ALPN protocol enabled.
    pub fn with_socket_and_tls_config(
        socket: impl IntoQuicSocket,
        tls_config: Arc<TlsServerConfig>,
    ) -> Result<Self, NetError> {
        let endpoint = QuicEndpoint::new(
            socket,
            tls_config,
            quic_config::endpoint(),
            quic_config::transport(),
        )?;

        Ok(Self { endpoint })
    }

    /// Accept the next connection and its recorded metadata after completing its QUIC handshake.
    ///
    /// Handshakes run concurrently. The timeout applies to each individual handshake.
    /// Handshake failures are logged and skipped; synchronous accept errors are returned.
    /// Dropping the listener aborts pending handshakes without waiting for them to finish.
    ///
    /// Cancelling this future leaves already-started handshakes owned by the listener.
    /// A subsequent call can receive their completed connections.
    pub async fn accept(
        &mut self,
        timeout: Option<Duration>,
    ) -> Option<Result<Accepted<QuicConnection>, NetError>> {
        self.endpoint.accept(timeout).await
    }

    /// Returns the address this listener is listening on.
    ///
    /// This can be useful in tests, where a random port can be associated with the server by binding on `127.0.0.1:0` and then getting the
    ///   associated port address with this function.
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.endpoint.local_addr()
    }
}
