//! Async DNSTAP client that manages connections and sends events.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::DnsTransport;
use crate::dnstap_message;
use crate::framestream;

const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(30);

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
            endpoint: DnstapEndpoint::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6000)),
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

/// A raw DNS event queued for encoding and transmission.
///
/// The layer enqueues these lightweight structs on the worker thread; the
/// background sender task encodes them into protobuf frames off the hot path.
pub(crate) enum DnstapEvent {
    Query {
        src_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        transport: DnsTransport,
        query_bytes: Vec<u8>,
        query_time: (u64, u32),
    },
    Response {
        src_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        transport: DnsTransport,
        query_bytes: Vec<u8>,
        query_time: (u64, u32),
        response_bytes: Vec<u8>,
    },
}

pub(crate) fn query_types_from_config(config: &DnstapConfig) -> Vec<DnstapMessageType> {
    [
        (config.log_auth_query, DnstapMessageType::Auth),
        (config.log_client_query, DnstapMessageType::Client),
        (config.log_resolver_query, DnstapMessageType::Resolver),
    ]
    .into_iter()
    .filter_map(|(enabled, mt)| enabled.then_some(mt))
    .collect()
}

pub(crate) fn response_types_from_config(config: &DnstapConfig) -> Vec<DnstapMessageType> {
    [
        (config.log_auth_response, DnstapMessageType::Auth),
        (config.log_client_response, DnstapMessageType::Client),
        (config.log_resolver_response, DnstapMessageType::Resolver),
    ]
    .into_iter()
    .filter_map(|(enabled, mt)| enabled.then_some(mt))
    .collect()
}

/// Async DNSTAP client that sends protobuf-encoded messages over Frame Streams.
pub struct DnstapClient {
    sender: mpsc::Sender<DnstapEvent>,
    drop_count: Arc<AtomicU64>,
}

impl DnstapClient {
    /// Create a new DNSTAP client with the given configuration.
    ///
    /// Immediately spawns a background task that manages the connection and
    /// sends messages.  Must be called inside a Tokio runtime context.
    pub fn new(config: DnstapConfig) -> Self {
        let (sender, connection) = create_background_sender(
            config.endpoint.clone(),
            config.buffer_size,
            config.max_backoff,
            Arc::new(config.identity.clone()),
            Arc::new(config.version.clone()),
            query_types_from_config(&config),
            response_types_from_config(&config),
        );
        let drop_count = connection.drop_count();
        connection.start();
        Self { sender, drop_count }
    }

    /// Log a DNS query event.
    pub fn log_query(
        &self,
        src_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        transport: DnsTransport,
        query_bytes: &[u8],
    ) {
        self.send(DnstapEvent::Query {
            src_addr,
            server_addr,
            transport,
            query_bytes: query_bytes.to_vec(),
            query_time: dnstap_message::now_time(),
        });
    }

    /// Log a DNS response event.
    pub fn log_response(
        &self,
        src_addr: SocketAddr,
        server_addr: Option<SocketAddr>,
        transport: DnsTransport,
        query_bytes: &[u8],
        query_time: (u64, u32),
        response_bytes: &[u8],
    ) {
        self.send(DnstapEvent::Response {
            src_addr,
            server_addr,
            transport,
            query_bytes: query_bytes.to_vec(),
            query_time,
            response_bytes: response_bytes.to_vec(),
        });
    }

    fn send(&self, event: DnstapEvent) {
        if self.sender.try_send(event).is_err() {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Create the mpsc channel for the DNSTAP background sender.
///
/// Returns the sender (for the layer to enqueue events) and a
/// [`DnstapConnection`] that must be [`start`](DnstapConnection::start)ed
/// inside a Tokio runtime to actually connect and drain the channel.
pub(crate) fn create_background_sender(
    endpoint: DnstapEndpoint,
    buffer_size: usize,
    max_backoff: Duration,
    identity: Arc<Option<Vec<u8>>>,
    version: Arc<Option<Vec<u8>>>,
    query_types: Vec<DnstapMessageType>,
    response_types: Vec<DnstapMessageType>,
) -> (mpsc::Sender<DnstapEvent>, DnstapConnection) {
    let (sender, receiver) = mpsc::channel(buffer_size);
    let conn = DnstapConnection {
        endpoint,
        max_backoff,
        receiver,
        drop_count: Arc::new(AtomicU64::new(0)),
        encoder: EncoderConfig {
            identity,
            version,
            query_types,
            response_types,
        },
    };
    (sender, conn)
}

/// Encoding parameters shared between the layer/client and the background task.
struct EncoderConfig {
    identity: Arc<Option<Vec<u8>>>,
    version: Arc<Option<Vec<u8>>>,
    query_types: Vec<DnstapMessageType>,
    response_types: Vec<DnstapMessageType>,
}

/// Handle for the not-yet-spawned DNSTAP background sender.
///
/// Call [`start`](Self::start) once the server is ready to accept connections
/// so that the connection handshake log appears in the right place in the
/// startup output.
pub struct DnstapConnection {
    endpoint: DnstapEndpoint,
    max_backoff: Duration,
    receiver: mpsc::Receiver<DnstapEvent>,
    drop_count: Arc<AtomicU64>,
    encoder: EncoderConfig,
}

impl DnstapConnection {
    /// Returns a clone of the shared drop counter.
    ///
    /// The same counter is used by the background sender to report dropped
    /// messages, so the layer and the sender stay in sync without extra
    /// coordination.
    pub(crate) fn drop_count(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.drop_count)
    }

    /// Spawn the background sender task.
    ///
    /// The task connects to the DNSTAP endpoint, performs the Frame Streams
    /// handshake, and begins draining queued frames.
    pub fn start(self) {
        tokio::spawn(background_sender(
            self.endpoint,
            self.max_backoff,
            self.receiver,
            self.drop_count,
            self.encoder,
        ));
    }
}

async fn background_sender(
    endpoint: DnstapEndpoint,
    max_backoff: Duration,
    mut receiver: mpsc::Receiver<DnstapEvent>,
    drop_count: Arc<AtomicU64>,
    enc: EncoderConfig,
) {
    let mut backoff = Duration::from_millis(100);

    loop {
        match connect_and_send(&endpoint, &mut receiver, &drop_count, &enc).await {
            Ok(()) => {
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

async fn connect_and_send(
    endpoint: &DnstapEndpoint,
    receiver: &mut mpsc::Receiver<DnstapEvent>,
    drop_count: &AtomicU64,
    enc: &EncoderConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match endpoint {
        DnstapEndpoint::Tcp(addr) => {
            debug!("dnstap connecting to TCP {addr}");
            let stream = tokio::net::TcpStream::connect(addr).await?;
            run_stream(stream, receiver, drop_count, enc).await
        }
        #[cfg(unix)]
        DnstapEndpoint::Unix(path) => {
            debug!("dnstap connecting to Unix socket {}", path.display());
            let stream = tokio::net::UnixStream::connect(path).await?;
            run_stream(stream, receiver, drop_count, enc).await
        }
    }
}

/// Run the Frame Streams protocol over a connected stream.
async fn run_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    receiver: &mut mpsc::Receiver<DnstapEvent>,
    drop_count: &AtomicU64,
    enc: &EncoderConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    framestream::handshake(&mut stream).await?;

    let dropped = drop_count.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        warn!("{dropped} dnstap messages dropped while collector was unreachable");
    }
    info!("dnstap connection handshake completed");

    let mut interval = tokio::time::interval(DROP_REPORT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            msg = receiver.recv() => {
                let Some(event) = msg else { break; };
                encode_and_write(&mut stream, event, enc).await?;
            }
            _ = interval.tick() => {
                let dropped = drop_count.swap(0, Ordering::Relaxed);
                if dropped > 0 {
                    warn!("{dropped} dnstap messages dropped in the last 30s (channel full)");
                }
            }
        }
    }

    // Channel closed, do graceful shutdown
    framestream::shutdown(&mut stream).await?;
    Ok(())
}

async fn encode_and_write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    event: DnstapEvent,
    enc: &EncoderConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match event {
        DnstapEvent::Query {
            src_addr,
            server_addr,
            transport,
            query_bytes,
            query_time,
        } => {
            for message_type in &enc.query_types {
                let encoded = dnstap_message::build_query(&dnstap_message::DnstapEventParams {
                    identity: &enc.identity,
                    version: &enc.version,
                    src_addr,
                    server_addr,
                    transport,
                    query_bytes: &query_bytes,
                    query_time,
                    message_type,
                });
                stream
                    .write_all(&framestream::build_data_frame(&encoded))
                    .await?;
            }
        }
        DnstapEvent::Response {
            src_addr,
            server_addr,
            transport,
            query_bytes,
            query_time,
            response_bytes,
        } => {
            for message_type in &enc.response_types {
                let encoded = dnstap_message::build_response(
                    &dnstap_message::DnstapEventParams {
                        identity: &enc.identity,
                        version: &enc.version,
                        src_addr,
                        server_addr,
                        transport,
                        query_bytes: &query_bytes,
                        query_time,
                        message_type,
                    },
                    &response_bytes,
                );
                stream
                    .write_all(&framestream::build_data_frame(&encoded))
                    .await?;
            }
        }
    }
    Ok(())
}

/// Create a DNSTAP client that sends to a pre-connected stream (for testing).
#[cfg(test)]
pub(crate) fn new_with_sender(
    sender: mpsc::Sender<DnstapEvent>,
    _identity: Option<Vec<u8>>,
    _version: Option<Vec<u8>>,
) -> DnstapClient {
    DnstapClient {
        sender,
        drop_count: Arc::new(AtomicU64::new(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_channel_drops_when_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let client = new_with_sender(sender, None, None);

        client.log_query(
            "127.0.0.1:1234".parse().unwrap(),
            None,
            DnsTransport::Udp,
            b"\x00\x01",
        );

        // Second send should be dropped without panic
        client.log_query(
            "127.0.0.1:1234".parse().unwrap(),
            None,
            DnsTransport::Udp,
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
            DnsTransport::Tcp,
            b"\xab\xcd",
        );

        assert!(receiver.try_recv().is_ok(), "expected an event in channel");
    }

    #[tokio::test]
    async fn test_client_sends_response_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(sender, None, None);

        client.log_response(
            "10.0.0.1:53".parse().unwrap(),
            None,
            DnsTransport::Udp,
            b"\x00\x01",
            (1_000_000, 0),
            b"\x00\x01\x80\x00",
        );

        assert!(receiver.try_recv().is_ok(), "expected an event in channel");
    }
}
