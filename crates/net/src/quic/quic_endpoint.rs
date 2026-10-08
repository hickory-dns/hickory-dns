use std::{fmt, future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connecting, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig};
use rustls::ServerConfig as TlsServerConfig;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::IntoQuicSocket;
use crate::{error::NetError, runtime::Accepted, utils, utils::sanitize_src_address};

/// QUIC and HTTP/3 share acceptance and task ownership but initialize different protocols.
pub(crate) trait QuicHandshake: Sized + Send + 'static {
    /// Returns a Send future that completes protocol initialization.
    fn handshake(connecting: Connecting) -> impl Future<Output = Result<Self, NetError>> + Send;
}

/// Keeping handshake tasks here preserves them across cancelled accept calls and cancels
/// them when the listener is dropped.
pub(crate) struct QuicEndpoint<H> {
    endpoint: Endpoint,
    handshakes: JoinSet<Option<Accepted<H>>>,
}

impl<H> fmt::Debug for QuicEndpoint<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicEndpoint")
            .field("endpoint", &self.endpoint)
            .field("handshakes", &self.handshakes)
            .finish()
    }
}

impl<H: QuicHandshake> QuicEndpoint<H> {
    pub(crate) fn new(
        socket: impl IntoQuicSocket,
        tls_config: Arc<TlsServerConfig>,
        endpoint_config: EndpointConfig,
        transport_config: TransportConfig,
    ) -> Result<Self, NetError> {
        let mut server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
        server_config.transport = Arc::new(transport_config);

        let socket = socket.into_quic_socket()?;
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )?;

        Ok(Self {
            endpoint,
            handshakes: JoinSet::new(),
        })
    }

    async fn handshake(
        connecting: Connecting,
        src_addr: SocketAddr,
        timeout: Option<Duration>,
    ) -> Option<Accepted<H>> {
        debug!(%src_addr, "starting QUIC request");

        let connection = utils::timeout(timeout, H::handshake(connecting))
            .await
            .inspect_err(|_| warn!("timeout expired during handshake"))
            .ok()?
            .inspect_err(|error| debug!(%error, "error completing incoming quic connection"))
            .ok()?;

        debug!(%src_addr, "accepted QUIC request");
        Some(Accepted {
            connection,
            src_addr,
        })
    }

    pub(crate) async fn accept(
        &mut self,
        timeout: Option<Duration>,
    ) -> Option<Result<Accepted<H>, NetError>> {
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let incoming = incoming?;
                    let src_addr = incoming.remote_address();
                    // Require address validation before allocating connection state for a spoofable peer.
                    if !incoming.remote_address_validated() {
                        if let Err(error) = incoming.retry() {
                            warn!(%error, "could not send retry packet");
                        }
                        continue;
                    }
                    if let Err(error) = sanitize_src_address(src_addr) {
                        warn!(%error, %src_addr, "address can not be responded to");
                        continue;
                    }
                    let connecting = match incoming.accept() {
                        Ok(connecting) => connecting,
                        Err(error) => return Some(Err(error.into())),
                    };
                    self.handshakes.spawn(Self::handshake(connecting, src_addr, timeout));
                }
                Some(result) = self.handshakes.join_next() => {
                    if let Ok(Some(connection)) = result {
                        return Some(Ok(connection));
                    };
                }
            }
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}
