// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP/3 related server items

use core::net::SocketAddr;
use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

use bytes::Bytes;
use h3::server::{Connection, RequestResolver};
use h3_quinn::Endpoint;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{
    AsyncUdpSocket, Connecting, EndpointConfig, Incoming, Runtime, ServerConfig, TokioRuntime,
};
use rustls::server::ResolvesServerCert;
use rustls::server::ServerConfig as TlsServerConfig;
use rustls::version::TLS13;

use crate::{error::NetError, tls::default_provider};

use super::ALPN_H3;

/// A DNS-over-HTTP/3 Server, see H3ClientStream for the client counterpart
pub struct H3Server {
    endpoint: Endpoint,
}

impl H3Server {
    /// Construct the new Acceptor with the associated pkcs12 data
    pub async fn new(
        name_server: SocketAddr,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        // setup a new socket for the server to use
        let socket = TokioRuntime.wrap_udp_socket(UdpSocket::bind(name_server)?)?;
        Self::with_socket(socket, server_cert_resolver)
    }

    /// Construct the new server with an existing socket and default TLS config.
    pub fn with_socket(
        socket: Arc<dyn AsyncUdpSocket>,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, NetError> {
        let mut config = TlsServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&TLS13])
            .expect("TLS1.3 not supported")
            .with_no_client_auth()
            .with_cert_resolver(server_cert_resolver);

        config.alpn_protocols = vec![ALPN_H3.to_vec()];

        Self::with_socket_and_tls_config(socket, Arc::new(config))
    }

    /// Construct the new server with an existing socket and custom TLS config.
    ///
    /// The TLS configuration should support TLS 1.3 and have the H3 ALPN protocol enabled.
    pub fn with_socket_and_tls_config(
        socket: Arc<dyn AsyncUdpSocket>,
        tls_config: Arc<TlsServerConfig>,
    ) -> Result<Self, NetError> {
        let mut server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
        server_config.transport = Arc::new(super::transport());

        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self { endpoint })
    }

    /// Accept the next incoming connection.
    ///
    /// # Returns
    ///
    /// A remote connection that could accept many potential requests and the remote socket address
    pub async fn accept(&mut self) -> Option<Incoming> {
        self.endpoint.accept().await
    }

    /// Returns the address this server is listening on
    ///
    /// This can be useful in tests, where a random port can be associated with the server by binding on `127.0.0.1:0` and then getting the
    ///   associated port address with this function.
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.endpoint.local_addr()
    }
}

/// A HTTP/3 connection.
pub struct H3Connection {
    connection: Connection<h3_quinn::Connection, Bytes>,
}

impl H3Connection {
    /// Complete a QUIC handshake and set up an HTTP/3 connection.
    pub async fn new(connecting: Connecting) -> Result<Self, NetError> {
        let quinn_connection = connecting.await?;
        let h3_quinn_connection = h3_quinn::Connection::new(quinn_connection);
        let h3_connection = Connection::new(h3_quinn_connection)
            .await
            .map_err(|e| NetError::from(format!("h3 connection failed: {e}")))?;
        Ok(Self {
            connection: h3_connection,
        })
    }

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
