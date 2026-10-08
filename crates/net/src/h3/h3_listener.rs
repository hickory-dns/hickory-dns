// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP/3 related server items

use core::net::SocketAddr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::tls::tls_config;
use crate::{
    error::NetError,
    quic::{
        IntoQuicSocket,
        quic_endpoint::{QuicEndpoint, QuicHandshake},
    },
    runtime::Accepted,
};
use bytes::Bytes;
use h3::server::{Connection, RequestResolver};
use quinn::Connecting;
use rustls::server::ResolvesServerCert;
use rustls::server::ServerConfig as TlsServerConfig;
use tokio::net::UdpSocket;

/// An HTTP/3 connection.
pub struct H3Connection {
    connection: Connection<h3_quinn::Connection, Bytes>,
}

impl H3Connection {
    /// Accept the next request from the client
    pub async fn accept(
        &mut self,
    ) -> Result<Option<RequestResolver<h3_quinn::Connection, Bytes>>, NetError> {
        self.connection
            .accept()
            .await
            .map_err(|e| NetError::from(format!("h3 request failed: {e}")))
    }

    /// Shutdown the connection.
    pub async fn shutdown(&mut self) -> Result<(), NetError> {
        self.connection
            .shutdown(0)
            .await
            .map_err(|e| NetError::from(format!("h3 connection shutdown failed: {e}")))
    }
}

impl QuicHandshake for H3Connection {
    async fn handshake(connecting: Connecting) -> Result<Self, NetError> {
        let connection = Connection::new(h3_quinn::Connection::new(connecting.await?))
            .await
            .map_err(|e| NetError::from(format!("h3 connection failed: {e}")))?;
        Ok(Self { connection })
    }
}

/// A listener for established DNS-over-HTTP/3 connections.
#[derive(Debug)]
pub struct H3Listener {
    endpoint: QuicEndpoint<H3Connection>,
}

impl H3Listener {
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
        let config = tls_config::server_quic(b"h3", cert_resolver);
        Self::with_socket_and_tls_config(socket, Arc::new(config))
    }

    /// Constructs a listener with an existing socket and a custom TLS configuration.
    ///
    /// The TLS configuration should support TLS 1.3 and have the H3 ALPN protocol enabled.
    pub fn with_socket_and_tls_config(
        socket: impl IntoQuicSocket,
        tls_config: Arc<TlsServerConfig>,
    ) -> Result<Self, NetError> {
        let endpoint =
            QuicEndpoint::new(socket, tls_config, super::endpoint(), super::transport())?;

        Ok(Self { endpoint })
    }

    /// Accept the next connection and its recorded metadata after its QUIC and HTTP/3 handshakes.
    ///
    /// Handshakes run concurrently. The timeout covers both protocol initialization steps.
    /// Handshake failures are logged and skipped; synchronous accept errors are returned.
    /// Dropping the listener aborts pending handshakes without waiting for them to finish.
    ///
    /// Cancelling this future leaves already-started handshakes owned by the listener.
    /// A subsequent call can receive their completed connections.
    pub async fn accept(
        &mut self,
        timeout: Option<Duration>,
    ) -> Option<Result<Accepted<H3Connection>, NetError>> {
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
