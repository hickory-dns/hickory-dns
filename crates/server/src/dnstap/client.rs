//! Async DNSTAP client that manages connections and sends events.

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::net::xfer::Protocol;

use super::dnstap_message;
use super::framestream;

/// DNSTAP message type variants.
///
/// Determines which protobuf message type is used for query/response events.
#[derive(Clone, Copy, Debug)]
pub enum DnstapMessageType {
    /// AUTH_QUERY / AUTH_RESPONSE.
    Auth,
    /// CLIENT_QUERY / CLIENT_RESPONSE.
    Client,
    /// RESOLVER_QUERY / RESOLVER_RESPONSE.
    Resolver,
}

/// Configuration for the DNSTAP client.
#[derive(Clone, Debug)]
pub struct DnstapConfig {
    /// The endpoint to connect to (TCP address or Unix socket path).
    pub endpoint: DnstapEndpoint,
    /// DNS server identity (sent in DNSTAP messages).
    pub identity: Option<Vec<u8>>,
    /// DNS server version (sent in DNSTAP messages).
    pub version: Option<Vec<u8>>,
    /// Size of the internal channel buffer.
    pub buffer_size: usize,
    /// Maximum backoff duration for reconnection.
    pub max_backoff: Duration,
    /// Whether to log AUTH_QUERY messages.
    pub log_auth_query: bool,
    /// Whether to log AUTH_RESPONSE messages.
    pub log_auth_response: bool,
    /// Whether to log CLIENT_QUERY messages.
    pub log_client_query: bool,
    /// Whether to log CLIENT_RESPONSE messages.
    pub log_client_response: bool,
    /// Whether to log RESOLVER_QUERY messages.
    pub log_resolver_query: bool,
    /// Whether to log RESOLVER_RESPONSE messages.
    pub log_resolver_response: bool,
}

impl Default for DnstapConfig {
    fn default() -> Self {
        Self {
            endpoint: DnstapEndpoint::Tcp("127.0.0.1:6000".parse().unwrap()),
            identity: None,
            version: None,
            buffer_size: 4096,
            max_backoff: Duration::from_secs(30),
            log_auth_query: false,
            log_auth_response: false,
            log_client_query: false,
            log_client_response: false,
            log_resolver_query: false,
            log_resolver_response: false,
        }
    }
}

/// DNSTAP endpoint types.
#[derive(Clone, Debug)]
pub enum DnstapEndpoint {
    /// TCP socket address.
    Tcp(SocketAddr),
    /// Unix socket path.
    #[cfg(unix)]
    Unix(PathBuf),
}

/// Async DNSTAP client that sends protobuf-encoded messages over Frame Streams.
pub struct DnstapClient {
    sender: mpsc::Sender<Vec<u8>>,
    identity: Arc<Option<Vec<u8>>>,
    version: Arc<Option<Vec<u8>>>,
    log_auth_query: bool,
    log_auth_response: bool,
    log_client_query: bool,
    log_client_response: bool,
    log_resolver_query: bool,
    log_resolver_response: bool,
}

impl DnstapClient {
    /// Create a new DNSTAP client with the given configuration.
    ///
    /// Spawns a background task that manages the connection and sends messages.
    pub fn new(config: DnstapConfig) -> Self {
        let (sender, receiver) = mpsc::channel(config.buffer_size);

        let identity = Arc::new(config.identity.clone());
        let version = Arc::new(config.version.clone());

        tokio::spawn(background_sender(
            config.endpoint.clone(),
            config.max_backoff,
            receiver,
        ));

        Self {
            sender,
            identity,
            version,
            log_auth_query: config.log_auth_query,
            log_auth_response: config.log_auth_response,
            log_client_query: config.log_client_query,
            log_client_response: config.log_client_response,
            log_resolver_query: config.log_resolver_query,
            log_resolver_response: config.log_resolver_response,
        }
    }

    /// Returns the enabled query message types.
    fn enabled_query_types(&self) -> impl Iterator<Item = DnstapMessageType> {
        [
            (self.log_auth_query, DnstapMessageType::Auth),
            (self.log_client_query, DnstapMessageType::Client),
            (self.log_resolver_query, DnstapMessageType::Resolver),
        ]
        .into_iter()
        .filter_map(|(enabled, mt)| enabled.then_some(mt))
    }

    /// Returns the enabled response message types.
    fn enabled_response_types(&self) -> impl Iterator<Item = DnstapMessageType> {
        [
            (self.log_auth_response, DnstapMessageType::Auth),
            (self.log_client_response, DnstapMessageType::Client),
            (self.log_resolver_response, DnstapMessageType::Resolver),
        ]
        .into_iter()
        .filter_map(|(enabled, mt)| enabled.then_some(mt))
    }

    /// Log a DNS query event for each enabled query message type.
    pub fn log_query(
        &self,
        src_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        protocol: Protocol,
        query_bytes: &[u8],
    ) {
        for message_type in self.enabled_query_types() {
            let encoded = dnstap_message::build_query(&dnstap_message::DnstapEventParams {
                identity: &self.identity,
                version: &self.version,
                src_addr,
                server_addr,
                protocol,
                query_bytes,
                message_type: &message_type,
            });
            self.send(encoded);
        }
    }

    /// Log a DNS response event for each enabled response message type.
    pub fn log_response(
        &self,
        src_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        protocol: Protocol,
        query_bytes: &[u8],
        response_bytes: &[u8],
    ) {
        for message_type in self.enabled_response_types() {
            let encoded = dnstap_message::build_response(
                &dnstap_message::DnstapEventParams {
                    identity: &self.identity,
                    version: &self.version,
                    src_addr,
                    server_addr,
                    protocol,
                    query_bytes,
                    message_type: &message_type,
                },
                response_bytes,
            );
            self.send(encoded);
        }
    }

    /// Non-blocking send. Drops the message if the channel is full.
    fn send(&self, encoded: Vec<u8>) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.sender.try_send(encoded) {
            warn!("dnstap channel full, dropping message");
        }
    }
}

/// Background task that manages the DNSTAP connection.
async fn background_sender(
    endpoint: DnstapEndpoint,
    max_backoff: Duration,
    mut receiver: mpsc::Receiver<Vec<u8>>,
) {
    let mut backoff = Duration::from_millis(100);

    loop {
        match connect_and_send(&endpoint, &mut receiver).await {
            Ok(()) => {
                // Channel closed, shutting down
                info!("dnstap client shutting down");
                return;
            }
            Err(e) => {
                error!("dnstap connection error: {e}, reconnecting in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// Connect to the endpoint, perform handshake, and drain the channel.
async fn connect_and_send(
    endpoint: &DnstapEndpoint,
    receiver: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match endpoint {
        DnstapEndpoint::Tcp(addr) => {
            debug!("dnstap connecting to TCP {addr}");
            let stream = tokio::net::TcpStream::connect(addr).await?;
            run_stream(stream, receiver).await
        }
        #[cfg(unix)]
        DnstapEndpoint::Unix(path) => {
            debug!("dnstap connecting to Unix socket {}", path.display());
            let stream = tokio::net::UnixStream::connect(path).await?;
            run_stream(stream, receiver).await
        }
    }
}

/// Create a DNSTAP client that sends to a pre-connected stream (for testing).
#[cfg(test)]
pub(super) fn new_with_sender(
    sender: mpsc::Sender<Vec<u8>>,
    identity: Option<Vec<u8>>,
    version: Option<Vec<u8>>,
) -> DnstapClient {
    DnstapClient {
        sender,
        identity: Arc::new(identity),
        version: Arc::new(version),
        log_auth_query: true,
        log_auth_response: true,
        log_client_query: false,
        log_client_response: false,
        log_resolver_query: false,
        log_resolver_response: false,
    }
}

/// Run the Frame Streams protocol over a connected stream.
async fn run_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    receiver: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    framestream::handshake(&mut stream).await?;
    info!("dnstap connection handshake completed");

    while let Some(encoded) = receiver.recv().await {
        let frame = framestream::build_data_frame(&encoded);
        stream.write_all(&frame).await?;
    }

    // Channel closed, do graceful shutdown
    framestream::shutdown(&mut stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_channel_drops_when_full() {
        // Create a channel with buffer size 1
        let (sender, _receiver) = mpsc::channel(1);
        let client = new_with_sender(sender, None, None);

        // First send should succeed
        client.log_query(
            "127.0.0.1:1234".parse().unwrap(),
            None,
            Protocol::Udp,
            b"\x00\x01",
        );

        // Fill the channel — second send should be dropped without panic
        client.log_query(
            "127.0.0.1:1234".parse().unwrap(),
            None,
            Protocol::Udp,
            b"\x00\x02",
        );
    }

    #[tokio::test]
    async fn test_client_sends_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(sender, Some(b"hickory".to_vec()), Some(b"0.1".to_vec()));

        client.log_query(
            "10.0.0.1:53".parse().unwrap(),
            None,
            Protocol::Tcp,
            b"\xab\xcd",
        );

        let msg = receiver.try_recv().expect("expected a message in channel");
        assert!(!msg.is_empty());
    }

    #[tokio::test]
    async fn test_client_sends_response_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(sender, None, None);

        client.log_response(
            "10.0.0.1:53".parse().unwrap(),
            None,
            Protocol::Udp,
            b"\x00\x01",
            b"\x00\x01\x80\x00",
        );

        let msg = receiver.try_recv().expect("expected a message in channel");
        assert!(!msg.is_empty());
    }
}
