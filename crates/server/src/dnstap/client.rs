//! Async DNSTAP client that manages connections and sends events.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::net::xfer::Protocol;

use super::dnstap_message;
use super::framestream;

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
}

impl Default for DnstapConfig {
    fn default() -> Self {
        Self {
            endpoint: DnstapEndpoint::Tcp("127.0.0.1:6000".parse().unwrap()),
            identity: None,
            version: None,
            buffer_size: 4096,
            max_backoff: Duration::from_secs(30),
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
        }
    }

    /// Log a DNS query event (AUTH_QUERY).
    pub fn log_query(&self, src_addr: SocketAddr, protocol: Protocol, query_bytes: &[u8]) {
        let encoded = dnstap_message::build_query(
            &self.identity,
            &self.version,
            src_addr,
            protocol,
            query_bytes,
        );
        self.send(encoded);
    }

    /// Log a DNS response event (AUTH_RESPONSE).
    pub fn log_response(
        &self,
        src_addr: SocketAddr,
        protocol: Protocol,
        query_bytes: &[u8],
        response_bytes: &[u8],
    ) {
        let encoded = dnstap_message::build_response(
            &self.identity,
            &self.version,
            src_addr,
            protocol,
            query_bytes,
            response_bytes,
        );
        self.send(encoded);
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
        client.log_query("127.0.0.1:1234".parse().unwrap(), Protocol::Udp, b"\x00\x01");

        // Fill the channel — second send should be dropped without panic
        client.log_query("127.0.0.1:1234".parse().unwrap(), Protocol::Udp, b"\x00\x02");
    }

    #[tokio::test]
    async fn test_client_sends_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(
            sender,
            Some(b"hickory".to_vec()),
            Some(b"0.1".to_vec()),
        );

        client.log_query("10.0.0.1:53".parse().unwrap(), Protocol::Tcp, b"\xab\xcd");

        let msg = receiver.try_recv().expect("expected a message in channel");
        assert!(!msg.is_empty());
    }

    #[tokio::test]
    async fn test_client_sends_response_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(sender, None, None);

        client.log_response(
            "10.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
            b"\x00\x01",
            b"\x00\x01\x80\x00",
        );

        let msg = receiver.try_recv().expect("expected a message in channel");
        assert!(!msg.is_empty());
    }
}
