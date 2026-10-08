use std::{fmt, io, sync::Arc, time::Duration};

use rustls::ServerConfig;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::{
    runtime::{
        Accepted, DnsTcpListener,
        iocompat::{AsyncIoStdAsTokio, AsyncIoTokioAsStd},
    },
    tcp::TcpListener,
    utils,
};

/// An established server-side TLS stream over a DNS TCP stream.
pub type TlsServerStream<S> =
    AsyncIoTokioAsStd<tokio_rustls::server::TlsStream<AsyncIoStdAsTokio<S>>>;

/// Accepts TCP connections and performs concurrent TLS handshakes.
///
/// Unfinished handshakes are aborted when the listener is dropped.
pub struct TlsListener<L: DnsTcpListener> {
    listener: TcpListener<L>,
    acceptor: TlsAcceptor,
    handshakes: JoinSet<Option<Accepted<TlsServerStream<L::Stream>>>>,
}

impl<L: DnsTcpListener + fmt::Debug> fmt::Debug for TlsListener<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsListener")
            .field("listener", &self.listener)
            .field("handshakes", &self.handshakes)
            .finish_non_exhaustive()
    }
}

impl<L: DnsTcpListener> TlsListener<L> {
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
    ) -> Option<Accepted<TlsServerStream<L::Stream>>> {
        let src_addr = accepted.src_addr;
        debug!(%src_addr, "starting TLS request");

        let tls_stream = utils::timeout(
            timeout,
            acceptor.accept(AsyncIoStdAsTokio(accepted.connection)),
        )
        .await
        .inspect_err(|_| warn!("tls timeout expired during handshake"))
        .ok()?
        .inspect_err(|error| debug!(%src_addr, %error, "tls handshake error"))
        .ok()?;

        debug!(%src_addr, "accepted TLS request");
        Some(Accepted {
            connection: AsyncIoTokioAsStd(tls_stream),
            src_addr,
        })
    }

    /// Accepts an established TLS stream together with its recorded connection metadata.
    ///
    /// The optional timeout applies to each TLS handshake. Failed handshakes are ignored;
    /// errors from the underlying TCP listener are returned to the caller.
    /// Cancelling this future does not cancel handshakes that have already started;
    /// dropping the listener aborts them.
    pub async fn accept(
        &mut self,
        timeout: Option<Duration>,
    ) -> io::Result<Accepted<TlsServerStream<L::Stream>>> {
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    self.handshakes.spawn(Self::handshake(
                        result?,
                        self.acceptor.clone(),
                        timeout,
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
