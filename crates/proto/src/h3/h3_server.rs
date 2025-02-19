// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP/3 related server items

use alloc::sync::Arc;
use std::{io, net::SocketAddr};

use bytes::Bytes;
use h3::server::{Connection, RequestStream};
use h3_quinn::{BidiStream, Endpoint};
use http::Request;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{EndpointConfig, ServerConfig};
use rustls::server::ResolvesServerCert;
use rustls::server::ServerConfig as TlsServerConfig;
use rustls::version::TLS13;

use crate::{error::ProtoError, rustls::default_provider, udp::UdpSocket};

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
    ) -> Result<Self, ProtoError> {
        // setup a new socket for the server to use
        let socket = <tokio::net::UdpSocket as UdpSocket>::bind(name_server).await?;
        Self::with_socket(socket, server_cert_resolver)
    }

    /// Construct the new server with an existing socket
    pub fn with_socket(
        socket: tokio::net::UdpSocket,
        server_cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Self, ProtoError> {
        let mut config = TlsServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&TLS13])
            .expect("TLS1.3 not supported")
            .with_no_client_auth()
            .with_cert_resolver(server_cert_resolver);

        config.alpn_protocols = vec![ALPN_H3.to_vec()];

        let mut server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(config).unwrap()));
        server_config.transport = Arc::new(super::transport());

        let socket = socket.into_std()?;

        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;

        Ok(Self { endpoint })
    }

    /// Accept the next incoming connection.
    ///
    /// # Returns
    ///
    /// A remote connection that could accept many potential requests and the remote socket address
    pub async fn accept(&mut self) -> Result<Option<(H3Connection, SocketAddr)>, ProtoError> {
        let connecting = match self.endpoint.accept().await {
            Some(conn) => conn,
            None => return Ok(None),
        };

        let remote_addr = connecting.remote_address();
        let connection = connecting.await?;
        Ok(Some((
            H3Connection {
                connection: Connection::new(h3_quinn::Connection::new(connection))
                    .await
                    .map_err(|e| ProtoError::from(format!("h3 connection failed: {e}")))?,
            },
            remote_addr,
        )))
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
    /// Accept the next request from the client
    pub async fn accept(
        &mut self,
    ) -> Option<Result<(Request<()>, RequestStream<BidiStream<Bytes>, Bytes>), ProtoError>> {
        match self.connection.accept().await {
            Ok(Some((request, stream))) => Some(Ok((request, stream))),
            Ok(None) => None,
            Err(e) => Some(Err(ProtoError::from(format!("h3 request failed: {e}")))),
        }
    }

    /// Shutdown the connection.
    pub async fn shutdown(&mut self) -> Result<(), ProtoError> {
        self.connection
            .shutdown(0)
            .await
            .map_err(|e| ProtoError::from(format!("h3 connection shutdown failed: {e}")))
    }
}
