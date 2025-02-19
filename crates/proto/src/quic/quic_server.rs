// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::sync::Arc;
use std::{io, net::SocketAddr};

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::server::ResolvesServerCert;
use rustls::server::ServerConfig as TlsServerConfig;
use rustls::version::TLS13;

use crate::{error::ProtoError, rustls::default_provider, udp::UdpSocket};

use super::{
    quic_config,
    quic_stream::{self, QuicStream},
};

/// A DNS-over-QUIC Server, see QuicClientStream for the client counterpart
pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
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
            .unwrap() // The ring default provider is guaranteed to support TLS 1.3
            .with_no_client_auth()
            .with_cert_resolver(server_cert_resolver);

        config.alpn_protocols = vec![quic_stream::DOQ_ALPN.to_vec()];

        let mut server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(config)?));
        server_config.transport = Arc::new(quic_config::transport());

        let socket = socket.into_std()?;

        let endpoint_config = quic_config::endpoint();
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;

        Ok(Self { endpoint })
    }

    /// Get the next incoming stream
    ///
    /// # Returns
    ///
    /// A remote connection that could have many potential bi-directional streams and the remote socket address
    pub async fn next(&mut self) -> Result<Option<(QuicStreams, SocketAddr)>, ProtoError> {
        let connecting = match self.endpoint.accept().await {
            Some(conn) => conn,
            None => return Ok(None),
        };

        let remote_addr = connecting.remote_address();
        let connection = connecting.await?;
        Ok(Some((QuicStreams { connection }, remote_addr)))
    }

    /// Returns the address this server is listening on
    ///
    /// This can be useful in tests, where a random port can be associated with the server by binding on `127.0.0.1:0` and then getting the
    ///   associated port address with this function.
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.endpoint.local_addr()
    }
}

/// A stream of bi-directional QUIC streams
pub struct QuicStreams {
    connection: Connection,
}

impl QuicStreams {
    /// Get the next bi directional stream from the client
    pub async fn next(&mut self) -> Option<Result<QuicStream, ProtoError>> {
        match self.connection.accept_bi().await {
            Ok((send_stream, receive_stream)) => {
                Some(Ok(QuicStream::new(send_stream, receive_stream)))
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}
