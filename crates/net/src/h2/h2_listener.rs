use core::fmt::{self, Debug};
use core::net::SocketAddr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use h2::server::{Connection, SendResponse, handshake};
use http::Request;
use rustls::ServerConfig;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

use crate::error::NetError;
use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::runtime::{Accepted, DnsTcpListener, DnsTcpStream};
use crate::tcp::TcpListener;
use crate::utils;

/// An established server-side HTTP/2 connection over a DNS TCP stream.
pub struct H2Connection<S: DnsTcpStream> {
    connection: Connection<TlsStream<AsyncIoStdAsTokio<S>>, Bytes>,
    src_addr: SocketAddr,
}

impl<S: DnsTcpStream> Debug for H2Connection<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H2Connection")
            .field("src_addr", &self.src_addr)
            .finish_non_exhaustive()
    }
}

impl<S: DnsTcpStream> H2Connection<S> {
    /// Performs the HTTP/2 handshake on an established TLS stream.
    pub async fn new(
        stream: TlsStream<AsyncIoStdAsTokio<S>>,
        src_addr: SocketAddr,
    ) -> Result<Self, NetError> {
        Ok(Self {
            connection: handshake(stream).await?,
            src_addr,
        })
    }

    /// Returns the source address recorded when the TCP connection was accepted.
    pub fn src_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Accepts the next HTTP/2 request.
    pub async fn accept(
        &mut self,
    ) -> Option<Result<(Request<RecvStream>, SendResponse<Bytes>), NetError>> {
        self.connection
            .accept()
            .await
            .map(|result| result.map_err(Into::into))
    }
}

/// Accepts TCP connections and performs concurrent TLS and HTTP/2 handshakes.
///
/// Unfinished handshakes are aborted when the listener is dropped.
pub struct H2Listener<L: DnsTcpListener> {
    listener: TcpListener<L>,
    acceptor: TlsAcceptor,
    handshakes: JoinSet<Option<H2Connection<L::Stream>>>,
}

impl<L: DnsTcpListener + Debug> Debug for H2Listener<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H2Listener")
            .field("listener", &self.listener)
            .field("handshakes", &self.handshakes)
            .finish_non_exhaustive()
    }
}

impl<L: DnsTcpListener> H2Listener<L> {
    /// Wraps an already-bound TCP listener with the supplied TLS configuration.
    pub fn new(listener: L, tls_config: Arc<ServerConfig>) -> Self {
        Self {
            listener: TcpListener::new(listener),
            acceptor: TlsAcceptor::from(tls_config),
            handshakes: JoinSet::new(),
        }
    }

    async fn handshake(
        accepted: Accepted<L::Stream>,
        acceptor: TlsAcceptor,
        timeout: Option<Duration>,
    ) -> Option<H2Connection<L::Stream>> {
        let src_addr = accepted.src_addr;
        debug!("starting HTTPS request from: {src_addr}");

        let tls_stream = utils::timeout(
            timeout,
            acceptor.accept(AsyncIoStdAsTokio(accepted.connection)),
        )
        .await
        .inspect_err(|_| warn!("https timeout expired during handshake"))
        .ok()?
        .inspect_err(|error| debug!("https handshake src: {src_addr} error: {error}"))
        .ok()?;

        debug!("accepted HTTPS request from: {src_addr}");

        H2Connection::new(tls_stream, src_addr)
            .await
            .inspect_err(|error| warn!(%src_addr, %error, "handshake error"))
            .ok()
    }

    /// Accepts an established HTTP/2 connection together with its recorded metadata.
    ///
    /// The optional timeout applies only to the TLS handshake. Failed TLS or HTTP/2
    /// handshakes are ignored; errors from the underlying TCP listener are returned.
    /// Cancelling this future does not cancel handshakes that have already started;
    /// dropping the listener aborts them.
    pub async fn accept(
        &mut self,
        handshake_timeout: Option<Duration>,
    ) -> io::Result<H2Connection<L::Stream>> {
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    self.handshakes.spawn(Self::handshake(
                        result?,
                        self.acceptor.clone(),
                        handshake_timeout,
                    ));
                }
                Some(result) = self.handshakes.join_next() => {
                    if let Ok(Some(connection)) = result {
                        return Ok(connection);
                    };
                }
            }
        }
    }
}
