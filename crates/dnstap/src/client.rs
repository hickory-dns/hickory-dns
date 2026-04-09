//! Async DNSTAP client that manages connections and sends events.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(test)]
use bytes::Bytes;
use futures_util::{Sink, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::DnsTransport;
use crate::dnstap_message;
use crate::framestream::{self, FrameStreamCodec, FrameStreamItem};
#[cfg(feature = "metrics")]
use crate::metrics::DnstapMetrics;

const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// How long the shutdown waits for the collector's FINISH before giving up.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// DNSTAP message type variants.
///
/// Determines which protobuf message type is used for query/response events.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DnstapMessageType {
    /// AUTH_QUERY / AUTH_RESPONSE.
    Auth,
    /// CLIENT_QUERY / CLIENT_RESPONSE.
    Client,
    /// RESOLVER_QUERY / RESOLVER_RESPONSE.
    Resolver,
    /// UPDATE_QUERY / UPDATE_RESPONSE, used when the message opcode is UPDATE.
    Update,
}

/// Message bytes budgeted per queued event.
///
/// The queue is bounded by both count and bytes, so a burst of large responses
/// cannot hold more than [`DnstapConfig::buffer_size`] times this figure.
pub const QUEUED_BYTES_PER_EVENT: usize = 2 * 1024;

/// Configuration for the DNSTAP client.
#[derive(Clone, Debug)]
pub struct DnstapConfig {
    /// The endpoint to connect to (TCP address or Unix socket path).
    pub endpoint: DnstapEndpoint,
    /// DNS server identity, sent with every message; omitted when `None`.
    pub identity: Option<Vec<u8>>,
    /// DNS server version, sent with every message; omitted when `None`.
    pub version: Option<Vec<u8>>,
    /// Events queued for the sender before new ones are dropped, clamped to at
    /// least 1. Defaults to 4096.
    ///
    /// Queue memory is also bounded by [`QUEUED_BYTES_PER_EVENT`], so large
    /// responses fill the queue sooner than the count suggests.
    pub buffer_size: usize,
    /// Maximum backoff duration for reconnection, clamped to at least the
    /// 100 ms initial backoff. Defaults to 30 seconds.
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
    /// Whether to log UPDATE_QUERY messages.
    pub log_update_query: bool,
    /// Whether to log UPDATE_RESPONSE messages.
    pub log_update_response: bool,
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
            log_update_query: false,
            log_update_response: false,
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
///
/// The message type is classified by the emitter; each event yields exactly
/// one frame.
#[derive(Debug)]
pub(crate) struct DnstapEvent {
    pub(crate) message_type: DnstapMessageType,
    pub(crate) src_addr: Option<SocketAddr>,
    pub(crate) server_addr: Option<SocketAddr>,
    pub(crate) transport: Option<DnsTransport>,
    pub(crate) query_time: (u64, u32),
    pub(crate) query_zone: Option<Vec<u8>>,
    pub(crate) payload: EventPayload,
}

/// The DNS message bytes an event carries. Responses also carry the time
/// they were emitted, recorded before queueing so the timestamp does not
/// drift with sender backlog.
#[derive(Debug)]
pub(crate) enum EventPayload {
    Query {
        bytes: Vec<u8>,
    },
    Response {
        bytes: Vec<u8>,
        response_time: (u64, u32),
    },
}

impl EventPayload {
    /// The DNS message bytes, query or response.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Query { bytes } | Self::Response { bytes, .. } => bytes,
        }
    }

    /// The response emit time; `None` for queries.
    pub(crate) fn response_time(&self) -> Option<(u64, u32)> {
        match self {
            Self::Query { .. } => None,
            Self::Response { response_time, .. } => Some(*response_time),
        }
    }
}

impl DnstapEvent {
    /// Whether the event carries a query rather than a response.
    pub(crate) fn is_query(&self) -> bool {
        matches!(self.payload, EventPayload::Query { .. })
    }

    fn payload_len(&self) -> usize {
        // Accounted bytes for the queue budget: the DNS payload plus the
        // query zone, the per-event heap this event holds while queued.
        self.payload.bytes().len() + self.query_zone.as_ref().map_or(0, Vec::len)
    }
}

/// Per-direction, per-category filter built from `log_*` config flags.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MessageTypeFilter {
    auth_query: bool,
    auth_response: bool,
    client_query: bool,
    client_response: bool,
    resolver_query: bool,
    resolver_response: bool,
    update_query: bool,
    update_response: bool,
}

impl MessageTypeFilter {
    /// A filter that allows every message type, so the drop-counting tests
    /// reach the channel.
    #[cfg(test)]
    pub(crate) fn permissive() -> Self {
        Self {
            auth_query: true,
            auth_response: true,
            client_query: true,
            client_response: true,
            resolver_query: true,
            resolver_response: true,
            update_query: true,
            update_response: true,
        }
    }

    pub(crate) fn from_config(config: &DnstapConfig) -> Self {
        Self {
            auth_query: config.log_auth_query,
            auth_response: config.log_auth_response,
            client_query: config.log_client_query,
            client_response: config.log_client_response,
            resolver_query: config.log_resolver_query,
            resolver_response: config.log_resolver_response,
            update_query: config.log_update_query,
            update_response: config.log_update_response,
        }
    }

    pub(crate) fn allows(&self, message_type: DnstapMessageType, query: bool) -> bool {
        match (query, message_type) {
            (true, DnstapMessageType::Auth) => self.auth_query,
            (false, DnstapMessageType::Auth) => self.auth_response,
            (true, DnstapMessageType::Client) => self.client_query,
            (false, DnstapMessageType::Client) => self.client_response,
            (true, DnstapMessageType::Resolver) => self.resolver_query,
            (false, DnstapMessageType::Resolver) => self.resolver_response,
            (true, DnstapMessageType::Update) => self.update_query,
            (false, DnstapMessageType::Update) => self.update_response,
        }
    }
}

/// Async DNSTAP client that sends protobuf-encoded messages over Frame Streams.
pub struct DnstapClient {
    queue: EventQueue,
}

impl DnstapClient {
    /// Create a new DNSTAP client with the given configuration.
    ///
    /// Immediately spawns a background task that manages the connection and
    /// sends messages.  Must be called inside a Tokio runtime context.
    pub fn new(config: DnstapConfig) -> Self {
        let (queue, connection) = EventQueue::new(config);
        connection.start();
        Self { queue }
    }

    /// Log a DNS query event.
    ///
    /// The message type is classified by the caller.
    pub fn log_query(
        &self,
        message_type: DnstapMessageType,
        src_addr: Option<SocketAddr>,
        server_addr: Option<SocketAddr>,
        transport: Option<DnsTransport>,
        query_bytes: &[u8],
    ) {
        self.send(DnstapEvent {
            message_type,
            src_addr,
            server_addr,
            transport,
            query_zone: None,
            query_time: dnstap_message::now_time(),
            payload: EventPayload::Query {
                bytes: query_bytes.to_vec(),
            },
        });
    }

    /// Log a DNS response event.
    ///
    /// The message type is classified by the caller.
    pub fn log_response(
        &self,
        message_type: DnstapMessageType,
        src_addr: Option<SocketAddr>,
        server_addr: Option<SocketAddr>,
        transport: Option<DnsTransport>,
        query_time: (u64, u32),
        response_bytes: &[u8],
    ) {
        self.send(DnstapEvent {
            message_type,
            src_addr,
            server_addr,
            transport,
            query_zone: None,
            query_time,
            payload: EventPayload::Response {
                bytes: response_bytes.to_vec(),
                response_time: dnstap_message::now_time(),
            },
        });
    }

    fn send(&self, event: DnstapEvent) {
        self.queue.send(event);
    }
}

/// The channel, filter, and counters that events are sent through.
///
/// The client and the tracing layer both hold one, so the filter check and
/// the drop accounting live in one place.
pub(crate) struct EventQueue {
    sender: mpsc::Sender<DnstapEvent>,
    filter: MessageTypeFilter,
    drop_count: Arc<AtomicU64>,
    budget: Arc<ByteBudget>,
    #[cfg(feature = "metrics")]
    metrics: DnstapMetrics,
}

impl EventQueue {
    /// Build the queue and the connection handle for `config`.
    pub(crate) fn new(config: DnstapConfig) -> (Self, DnstapConnection) {
        let filter = MessageTypeFilter::from_config(&config);
        let (sender, connection) = create_background_sender(
            config.endpoint,
            config.buffer_size,
            config.max_backoff,
            Arc::new(config.identity),
            Arc::new(config.version),
        );
        let queue = Self {
            sender,
            filter,
            drop_count: Arc::clone(&connection.drop_count),
            budget: Arc::clone(&connection.budget),
            #[cfg(feature = "metrics")]
            metrics: connection.metrics.clone(),
        };
        (queue, connection)
    }

    pub(crate) fn send(&self, event: DnstapEvent) {
        if !self.filter.allows(event.message_type, event.is_query()) {
            return;
        }
        enqueue(
            &self.sender,
            &self.budget,
            &self.drop_count,
            #[cfg(feature = "metrics")]
            &self.metrics,
            event,
        );
    }

    /// Queue over an existing channel, for tests that read the events.
    #[cfg(test)]
    pub(crate) fn with_sender(
        sender: mpsc::Sender<DnstapEvent>,
        filter: MessageTypeFilter,
    ) -> Self {
        let budget = Arc::new(ByteBudget::for_buffer(sender.max_capacity()));
        Self {
            sender,
            filter,
            drop_count: Arc::new(AtomicU64::new(0)),
            budget,
            #[cfg(feature = "metrics")]
            metrics: DnstapMetrics::default(),
        }
    }
}

/// Tracks queued bytes against a limit.
///
/// Senders update the counts without a lock, so the cap can be passed for a
/// moment by one message per sender.
pub(crate) struct ByteBudget {
    limit: usize,
    bytes: AtomicUsize,
    events: AtomicUsize,
}

impl ByteBudget {
    /// Budget for a queue of `buffer_size` events.
    pub(crate) fn for_buffer(buffer_size: usize) -> Self {
        Self {
            limit: buffer_size.saturating_mul(QUEUED_BYTES_PER_EVENT),
            bytes: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
        }
    }

    fn try_reserve(&self, len: usize) -> bool {
        if self.bytes.fetch_add(len, Ordering::AcqRel) + len > self.limit {
            self.bytes.fetch_sub(len, Ordering::AcqRel);
            return false;
        }
        self.events.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn release(&self, len: usize) {
        self.bytes.fetch_sub(len, Ordering::AcqRel);
        self.events.fetch_sub(1, Ordering::AcqRel);
    }

    #[cfg(any(feature = "metrics", test))]
    fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    #[cfg(feature = "metrics")]
    fn events(&self) -> usize {
        self.events.load(Ordering::Acquire)
    }
}

pub(crate) fn enqueue(
    sender: &mpsc::Sender<DnstapEvent>,
    budget: &ByteBudget,
    drop_count: &AtomicU64,
    #[cfg(feature = "metrics")] metrics: &DnstapMetrics,
    event: DnstapEvent,
) {
    let len = event.payload_len();
    #[cfg(feature = "metrics")]
    let message_type = event.message_type;
    #[cfg(feature = "metrics")]
    let query = event.is_query();

    if budget.try_reserve(len) {
        if sender.try_send(event).is_ok() {
            return;
        }
        budget.release(len);
    }
    drop_count.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "metrics")]
    metrics.increment_dropped(message_type, query);
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
) -> (mpsc::Sender<DnstapEvent>, DnstapConnection) {
    // `mpsc::channel` panics on zero, so floor a misconfigured `buffer_size`.
    let buffer_size = buffer_size.max(1);
    let max_backoff = max_backoff.max(INITIAL_BACKOFF);
    let (sender, receiver) = mpsc::channel(buffer_size);
    let drop_count = Arc::new(AtomicU64::new(0));
    let conn = DnstapConnection {
        endpoint,
        max_backoff,
        receiver,
        drop_count: Arc::clone(&drop_count),
        budget: Arc::new(ByteBudget::for_buffer(buffer_size)),
        encoder: EncoderConfig { identity, version },
        #[cfg(feature = "metrics")]
        metrics: DnstapMetrics::default(),
    };
    (sender, conn)
}

/// Encoding parameters shared between the layer/client and the background task.
#[derive(Clone, Debug, Default)]
pub(crate) struct EncoderConfig {
    pub(crate) identity: Arc<Option<Vec<u8>>>,
    pub(crate) version: Arc<Option<Vec<u8>>>,
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
    budget: Arc<ByteBudget>,
    encoder: EncoderConfig,
    #[cfg(feature = "metrics")]
    metrics: DnstapMetrics,
}

impl DnstapConnection {
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
            self.budget,
            self.encoder,
            #[cfg(feature = "metrics")]
            self.metrics,
        ));
    }
}

async fn background_sender(
    endpoint: DnstapEndpoint,
    max_backoff: Duration,
    mut receiver: mpsc::Receiver<DnstapEvent>,
    drop_count: Arc<AtomicU64>,
    budget: Arc<ByteBudget>,
    enc: EncoderConfig,
    #[cfg(feature = "metrics")] metrics: DnstapMetrics,
) {
    let mut backoff = INITIAL_BACKOFF;

    loop {
        // A closed and empty queue means the client is gone; reconnecting
        // with nothing left to deliver would never end.
        if receiver.is_closed() && receiver.is_empty() {
            info!("dnstap client shutting down");
            return;
        }
        match connect_and_send(
            &endpoint,
            &mut receiver,
            &drop_count,
            &budget,
            enc.clone(),
            &mut backoff,
            #[cfg(feature = "metrics")]
            &metrics,
        )
        .await
        {
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
    budget: &ByteBudget,
    enc: EncoderConfig,
    backoff: &mut Duration,
    #[cfg(feature = "metrics")] metrics: &DnstapMetrics,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match endpoint {
        DnstapEndpoint::Tcp(addr) => {
            debug!("dnstap connecting to TCP {addr}");
            let stream = tokio::net::TcpStream::connect(addr).await?;
            run_stream(
                stream,
                receiver,
                drop_count,
                budget,
                enc,
                backoff,
                #[cfg(feature = "metrics")]
                metrics,
            )
            .await
        }
        #[cfg(unix)]
        DnstapEndpoint::Unix(path) => {
            debug!("dnstap connecting to Unix socket {}", path.display());
            let stream = tokio::net::UnixStream::connect(path).await?;
            run_stream(
                stream,
                receiver,
                drop_count,
                budget,
                enc,
                backoff,
                #[cfg(feature = "metrics")]
                metrics,
            )
            .await
        }
    }
}

/// Run the Frame Streams protocol over a connected stream.
///
/// Performs the handshake, then concurrently drains the event channel into
/// data frames and reads control frames from the collector. A
/// collector-initiated STOP is answered with FINISH and ends the session;
/// every error here triggers a reconnect in the caller.
async fn run_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    receiver: &mut mpsc::Receiver<DnstapEvent>,
    drop_count: &AtomicU64,
    budget: &ByteBudget,
    enc: EncoderConfig,
    backoff: &mut Duration,
    #[cfg(feature = "metrics")] metrics: &DnstapMetrics,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut framed = Framed::new(stream, FrameStreamCodec::with_encoder(enc));

    // Handshake: READY with our content type, the collector's ACCEPT echoing
    // it, then START.
    framed
        .send(FrameStreamItem::typed_control(framestream::CONTROL_READY))
        .await?;
    match framed.next().await {
        Some(Ok(FrameStreamItem::Control {
            control_type: framestream::CONTROL_ACCEPT,
            content_type,
        })) => match content_type.as_deref() {
            Some(ct) if ct == framestream::DNSTAP_CONTENT_TYPE => {}
            Some(ct) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "collector accepted content type {:?}, expected {:?}",
                        String::from_utf8_lossy(ct),
                        String::from_utf8_lossy(framestream::DNSTAP_CONTENT_TYPE),
                    ),
                )
                .into());
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "collector ACCEPT control frame carried no content type",
                )
                .into());
            }
        },
        Some(Ok(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected ACCEPT control frame",
            )
            .into());
        }
        Some(Err(e)) => return Err(e.into()),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed during handshake",
            )
            .into());
        }
    }
    framed
        .send(FrameStreamItem::typed_control(framestream::CONTROL_START))
        .await?;

    // The collector was just reachable, so restart the backoff sequence.
    *backoff = INITIAL_BACKOFF;

    let dropped = drop_count.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        warn!("{dropped} dnstap messages dropped while collector was unreachable");
    }
    info!("dnstap connection handshake completed");

    let mut interval = tokio::time::interval(DROP_REPORT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // consume the immediate first tick

    let (mut sink, mut collector) = framed.split();
    loop {
        tokio::select! {
            msg = receiver.recv() => {
                let Some(event) = msg else { break; };
                budget.release(event.payload_len());
                // Sample before the batch drain, which empties the queue.
                #[cfg(feature = "metrics")]
                metrics.set_queue(budget.events(), budget.bytes());
                send_event_batch(&mut sink, event, receiver, drop_count, budget, #[cfg(feature = "metrics")] metrics).await?;
            }
            frame = collector.next() => {
                match frame {
                    // The collector is ending the stream; reply FINISH and
                    // reconnect.
                    Some(Ok(FrameStreamItem::Control { control_type: framestream::CONTROL_STOP, .. })) => {
                        info!("dnstap collector sent STOP, closing stream");
                        sink.send(FrameStreamItem::bare_control(framestream::CONTROL_FINISH)).await?;
                        return Err(io::Error::other("dnstap collector sent STOP").into());
                    }
                    // A collector never sends data frames, and stray control
                    // frames carry no state the sender needs; ignore them.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "dnstap collector closed the connection",
                        )
                        .into())
                    }
                }
            }
            _ = interval.tick() => {
                let dropped = drop_count.swap(0, Ordering::Relaxed);
                if dropped > 0 {
                    warn!("{dropped} dnstap messages dropped in the last {DROP_REPORT_INTERVAL:?} (channel full)");
                }
            }
        }
    }

    // Channel closed: the client is gone, so deliver the STOP best-effort
    // and leave the socket for the collector to close. A failed write must
    // not schedule a reconnect with nothing left to deliver.
    if let Err(e) = sink
        .send(FrameStreamItem::bare_control(framestream::CONTROL_STOP))
        .await
    {
        debug!("dnstap teardown write failed: {e}");
        return Ok(());
    }
    // A FINISH closes the teardown cleanly; do not wait for a collector
    // that never answers.
    let _ = tokio::time::timeout(TEARDOWN_TIMEOUT, async {
        while let Some(frame) = collector.next().await {
            if matches!(
                frame,
                Ok(FrameStreamItem::Control {
                    control_type: framestream::CONTROL_FINISH,
                    ..
                })
            ) {
                break;
            }
        }
    })
    .await;
    Ok(())
}

/// Feed an event to the sink along with any events already queued on the
/// channel, then flush the batch with a single write.
///
/// Events still in the sink buffer when the write fails are lost with the
/// connection and counted as dropped.
async fn send_event_batch<S>(
    sink: &mut S,
    first: DnstapEvent,
    receiver: &mut mpsc::Receiver<DnstapEvent>,
    drop_count: &AtomicU64,
    budget: &ByteBudget,
    #[cfg(feature = "metrics")] metrics: &DnstapMetrics,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Sink<FrameStreamItem, Error = io::Error> + Unpin,
{
    // Message category and direction of each event in the batch.
    let mut batch: Vec<(DnstapMessageType, bool)> = vec![(first.message_type, first.is_query())];

    let result = async {
        sink.feed(FrameStreamItem::Event(first)).await?;
        // Coalesce any further events already queued behind this one; a
        // single flush writes the whole batch.
        while let Ok(next) = receiver.try_recv() {
            budget.release(next.payload_len());
            batch.push((next.message_type, next.is_query()));
            sink.feed(FrameStreamItem::Event(next)).await?;
        }
        sink.flush().await
    }
    .await;

    match result {
        Ok(()) => {
            #[cfg(feature = "metrics")]
            for (message_type, query) in &batch {
                metrics.increment_sent(*message_type, *query);
            }
            Ok(())
        }
        Err(e) => {
            drop_count.fetch_add(batch.len() as u64, Ordering::Relaxed);
            #[cfg(feature = "metrics")]
            for (message_type, query) in &batch {
                metrics.increment_dropped(*message_type, *query);
            }
            Err(e.into())
        }
    }
}

/// Create a DNSTAP client that sends to a pre-connected stream (for testing).
#[cfg(test)]
pub(crate) fn new_with_sender(sender: mpsc::Sender<DnstapEvent>) -> DnstapClient {
    DnstapClient {
        queue: EventQueue::with_sender(sender, MessageTypeFilter::permissive()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framestream::{
        CONTROL_ACCEPT, CONTROL_FINISH, CONTROL_READY, CONTROL_START, CONTROL_STOP,
    };
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    #[test]
    fn test_message_type_filter() {
        let filter = MessageTypeFilter::from_config(&DnstapConfig {
            log_client_query: true,
            log_update_query: true,
            ..Default::default()
        });

        assert!(filter.allows(DnstapMessageType::Client, true));
        assert!(!filter.allows(DnstapMessageType::Client, false));
        assert!(filter.allows(DnstapMessageType::Update, true));
        assert!(!filter.allows(DnstapMessageType::Update, false));
        assert!(!filter.allows(DnstapMessageType::Auth, true));
        assert!(!filter.allows(DnstapMessageType::Resolver, false));
    }

    #[tokio::test]
    async fn test_client_applies_message_type_filter() {
        let (sender, mut receiver) = mpsc::channel(8);
        let client = DnstapClient {
            queue: EventQueue::with_sender(
                sender,
                MessageTypeFilter::from_config(&DnstapConfig {
                    log_client_query: true,
                    ..Default::default()
                }),
            ),
        };

        client.log_query(
            DnstapMessageType::Client,
            Some("127.0.0.1:1234".parse().unwrap()),
            None,
            Some(DnsTransport::Udp),
            b"\x00\x01",
        );
        let event = receiver.try_recv().unwrap();
        assert!(event.is_query(), "expected a query event");
        assert_eq!(event.message_type, DnstapMessageType::Client);

        // The filter disables update queries, so this event is never queued.
        client.log_query(
            DnstapMessageType::Update,
            Some("127.0.0.1:1234".parse().unwrap()),
            None,
            Some(DnsTransport::Udp),
            b"\x00\x02",
        );
        assert!(
            receiver.try_recv().is_err(),
            "a filtered event must not reach the channel"
        );
    }

    #[tokio::test]
    async fn test_channel_drops_when_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let client = new_with_sender(sender);

        client.log_query(
            DnstapMessageType::Auth,
            Some("127.0.0.1:1234".parse().unwrap()),
            None,
            Some(DnsTransport::Udp),
            b"\x00\x01",
        );

        // Second send should be dropped without panic
        client.log_query(
            DnstapMessageType::Auth,
            Some("127.0.0.1:1234".parse().unwrap()),
            None,
            Some(DnsTransport::Udp),
            b"\x00\x02",
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_channel_drop_increments_dropped_counter() {
        use metrics::{Label, with_local_recorder};
        use metrics_util::debugging::DebuggingRecorder;
        use test_support::assert_counter_eq;

        use crate::metrics::{EVENTS_DROPPED_TOTAL, EVENTS_SENT_TOTAL};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let (sender, _receiver) = mpsc::channel(1);
            let client = new_with_sender(sender);

            client.log_query(
                DnstapMessageType::Auth,
                Some("127.0.0.1:1234".parse().unwrap()),
                None,
                Some(DnsTransport::Udp),
                b"\x00\x01",
            );
            // Channel is full; this one is dropped.
            client.log_query(
                DnstapMessageType::Auth,
                Some("127.0.0.1:1234".parse().unwrap()),
                None,
                Some(DnsTransport::Udp),
                b"\x00\x02",
            );
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();

        let labels = |direction| {
            vec![
                Label::new("category", "auth"),
                Label::new("direction", direction),
            ]
        };
        // Without a background task nothing drains the channel, so nothing is
        // counted as sent.
        assert_counter_eq(&map, EVENTS_SENT_TOTAL, labels("query"), 0);
        assert_counter_eq(&map, EVENTS_DROPPED_TOTAL, labels("query"), 1);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_run_stream_increments_sent_counter() {
        use metrics::{Label, with_local_recorder};
        use metrics_util::debugging::DebuggingRecorder;
        use test_support::assert_counter_eq;

        use crate::metrics::EVENTS_SENT_TOTAL;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        with_local_recorder(&recorder, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let (sender, mut receiver) = mpsc::channel(8);
                sender
                    .send(DnstapEvent {
                        message_type: DnstapMessageType::Auth,
                        src_addr: Some("127.0.0.1:1234".parse().unwrap()),
                        server_addr: None,
                        transport: Some(DnsTransport::Udp),
                        query_zone: None,
                        query_time: (1_000_000, 0),
                        payload: EventPayload::Query {
                            bytes: b"\x00\x01".to_vec(),
                        },
                    })
                    .await
                    .unwrap();
                drop(sender);

                let (client_side, server_side) = duplex(4096);
                let mut server = Framed::new(server_side, FrameStreamCodec::new());
                let server = tokio::spawn(async move {
                    mock_handshake(&mut server).await.unwrap();

                    let data = server.next().await.unwrap().unwrap();
                    assert!(
                        matches!(&data, FrameStreamItem::Data(payload) if !payload.is_empty()),
                        "expected a data frame, got {data:?}"
                    );

                    let stop = server.next().await.unwrap().unwrap();
                    assert!(
                        matches!(
                            stop,
                            FrameStreamItem::Control {
                                control_type: CONTROL_STOP,
                                ..
                            }
                        ),
                        "expected STOP, got {stop:?}"
                    );
                    server
                        .send(FrameStreamItem::bare_control(CONTROL_FINISH))
                        .await
                        .unwrap();
                });

                run_test_stream(client_side, &mut receiver).await.unwrap();

                server.await.unwrap();
            });
        });

        #[allow(clippy::mutable_key_type)]
        let map = snapshotter.snapshot().into_hashmap();
        let labels = vec![
            Label::new("category", "auth"),
            Label::new("direction", "query"),
        ];
        assert_counter_eq(&map, EVENTS_SENT_TOTAL, labels, 1);
    }

    #[tokio::test]
    async fn test_collector_stop_closes_stream() {
        // The sender stays open for the whole test, so the session can only
        // end through the collector's STOP.
        let (_keep_open, mut receiver) = mpsc::channel(8);

        let (client_side, server_side) = duplex(4096);
        let mut server = Framed::new(server_side, FrameStreamCodec::new());
        let server = tokio::spawn(async move {
            mock_handshake(&mut server).await.unwrap();

            server
                .send(FrameStreamItem::bare_control(CONTROL_STOP))
                .await
                .unwrap();
            let finish = server.next().await.unwrap().unwrap();
            assert!(
                matches!(
                    finish,
                    FrameStreamItem::Control {
                        control_type: CONTROL_FINISH,
                        ..
                    }
                ),
                "expected FINISH, got {finish:?}"
            );
        });

        let result = run_test_stream(client_side, &mut receiver).await;
        assert!(
            result.is_err(),
            "a collector STOP should end the session with an error"
        );

        server.await.unwrap();
    }

    /// A stalled collector must not grow the queue without limit: past the
    /// cap, messages are dropped and counted, so delivered plus dropped is
    /// every message offered.
    #[tokio::test]
    async fn test_byte_budget_bounds_queue_during_collector_stall() {
        const EVENTS: usize = 512;
        const PAYLOAD: usize = 64 * 1024;

        let (sender, mut receiver) = mpsc::channel(1024);
        let budget = Arc::new(ByteBudget::for_buffer(1024));
        let drop_count = Arc::new(AtomicU64::new(0));
        let resume = Arc::new(tokio::sync::Notify::new());

        let (client_side, server_side) = duplex(4096);
        let mut server = Framed::new(server_side, FrameStreamCodec::new());
        let collector_resume = Arc::clone(&resume);
        let collector = tokio::spawn(async move {
            mock_handshake(&mut server).await.unwrap();
            // Reading stops here so the sender blocks in flush, which is what
            // lets the queue fill.
            collector_resume.notified().await;

            let mut frames = 0usize;
            while let Some(frame) = server.next().await {
                match frame.unwrap() {
                    FrameStreamItem::Data(_) => frames += 1,
                    FrameStreamItem::Control {
                        control_type: CONTROL_STOP,
                        ..
                    } => {
                        server
                            .send(FrameStreamItem::bare_control(CONTROL_FINISH))
                            .await
                            .unwrap();
                        break;
                    }
                    _ => {}
                }
            }
            frames
        });

        let task_budget = Arc::clone(&budget);
        let task_drop_count = Arc::clone(&drop_count);
        let sender_task = tokio::spawn(async move {
            let mut backoff = INITIAL_BACKOFF;
            let enc = EncoderConfig {
                identity: Arc::new(None),
                version: Arc::new(None),
            };
            run_stream(
                client_side,
                &mut receiver,
                &task_drop_count,
                &task_budget,
                enc,
                &mut backoff,
                #[cfg(feature = "metrics")]
                &DnstapMetrics::default(),
            )
            .await
        });

        #[cfg(feature = "metrics")]
        let metrics = DnstapMetrics::default();
        for _ in 0..EVENTS {
            enqueue(
                &sender,
                &budget,
                &drop_count,
                #[cfg(feature = "metrics")]
                &metrics,
                DnstapEvent {
                    message_type: DnstapMessageType::Auth,
                    src_addr: None,
                    server_addr: None,
                    transport: Some(DnsTransport::Udp),
                    query_zone: None,
                    query_time: (1_000_000, 0),
                    payload: EventPayload::Response {
                        bytes: vec![0xa5; PAYLOAD],
                        response_time: (1_000_001, 0),
                    },
                },
            );
        }

        let refused = drop_count.load(Ordering::Relaxed);
        assert!(
            refused > 0,
            "the byte budget should refuse payloads past its limit"
        );
        assert!(
            budget.bytes() <= budget.limit,
            "queued payloads exceeded the byte budget: {} bytes",
            budget.bytes()
        );

        drop(sender);
        resume.notify_one();

        sender_task.await.unwrap().unwrap();
        let delivered = collector.await.unwrap();
        assert_eq!(
            delivered + refused as usize,
            EVENTS,
            "every offered event is delivered or counted as dropped"
        );
        assert_eq!(budget.bytes(), 0, "the queue should drain to empty");
    }

    #[tokio::test]
    async fn test_handshake_rejects_wrong_content_type() {
        let (_keep_open, mut receiver) = mpsc::channel(8);

        let (client_side, server_side) = duplex(4096);
        let mut server = Framed::new(server_side, FrameStreamCodec::new());
        let server = tokio::spawn(async move {
            let ready = server.next().await.unwrap().unwrap();
            assert!(
                matches!(
                    ready,
                    FrameStreamItem::Control {
                        control_type: CONTROL_READY,
                        ..
                    }
                ),
                "expected READY, got {ready:?}"
            );
            server
                .send(FrameStreamItem::Control {
                    control_type: CONTROL_ACCEPT,
                    content_type: Some(Bytes::from_static(b"protobuf:not-dnstap")),
                })
                .await
                .unwrap();
        });

        let result = run_test_stream(client_side, &mut receiver).await;
        assert!(
            result.is_err(),
            "a mismatched ACCEPT content type must fail the handshake"
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_rejects_missing_content_type() {
        let (_keep_open, mut receiver) = mpsc::channel(8);

        let (client_side, server_side) = duplex(4096);
        let mut server = Framed::new(server_side, FrameStreamCodec::new());
        let server = tokio::spawn(async move {
            let ready = server.next().await.unwrap().unwrap();
            assert!(
                matches!(
                    ready,
                    FrameStreamItem::Control {
                        control_type: CONTROL_READY,
                        ..
                    }
                ),
                "expected READY, got {ready:?}"
            );
            // An ACCEPT that carries no content type must be rejected.
            server
                .send(FrameStreamItem::bare_control(CONTROL_ACCEPT))
                .await
                .unwrap();
        });

        let result = run_test_stream(client_side, &mut receiver).await;
        assert!(
            result.is_err(),
            "an ACCEPT without a content type must fail the handshake"
        );

        server.await.unwrap();
    }

    #[test]
    fn test_degenerate_config_clamped() {
        let (sender, _connection) = create_background_sender(
            DnstapEndpoint::Tcp("127.0.0.1:1".parse().unwrap()),
            0,
            Duration::ZERO,
            Arc::new(None),
            Arc::new(None),
        );

        // A zero-capacity channel would lose nearly every event; the clamp
        // keeps at least one slot.
        sender
            .try_send(DnstapEvent {
                message_type: DnstapMessageType::Auth,
                src_addr: None,
                server_addr: None,
                transport: None,
                query_zone: None,
                query_time: (1_000_000, 0),
                payload: EventPayload::Query {
                    bytes: b"\x00\x01".to_vec(),
                },
            })
            .expect("a clamped channel still accepts an event");
    }

    #[tokio::test]
    async fn test_background_sender_exits_when_client_dropped() {
        // The client is gone and the collector is dead: the loop must exit
        // instead of retrying connects forever.
        let (_sender, receiver) = mpsc::channel(8);
        drop(_sender);

        let drop_count = Arc::new(AtomicU64::new(0));
        let enc = EncoderConfig {
            identity: Arc::new(None),
            version: Arc::new(None),
        };
        let sender_loop = background_sender(
            DnstapEndpoint::Tcp("127.0.0.1:1".parse().unwrap()),
            Duration::from_secs(30),
            receiver,
            Arc::clone(&drop_count),
            Arc::new(ByteBudget::for_buffer(8)),
            enc,
            #[cfg(feature = "metrics")]
            DnstapMetrics::default(),
        );

        tokio::time::timeout(Duration::from_secs(5), sender_loop)
            .await
            .expect("background_sender should exit once the client is gone");
    }

    #[tokio::test]
    async fn test_teardown_survives_collector_that_never_answers() {
        let (_keep_open, mut receiver) = mpsc::channel(8);
        // Close the client side so run_stream reaches its teardown.
        drop(_keep_open);

        let (client_side, server_side) = duplex(4096);
        let mut server = Framed::new(server_side, FrameStreamCodec::new());
        let _server_task = tokio::spawn(async move {
            mock_handshake(&mut server).await.unwrap();
            // Read the STOP but never reply FINISH, and hold the socket open.
            let stop = server.next().await.unwrap().unwrap();
            assert!(
                matches!(
                    stop,
                    FrameStreamItem::Control {
                        control_type: CONTROL_STOP,
                        ..
                    }
                ),
                "expected STOP, got {stop:?}"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        tokio::time::timeout(
            Duration::from_secs(5),
            run_test_stream(client_side, &mut receiver),
        )
        .await
        .expect("teardown should not wait forever for FINISH")
        .unwrap();
    }

    #[tokio::test]
    async fn test_client_sends_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(sender);

        client.log_query(
            DnstapMessageType::Auth,
            Some("10.0.0.1:53".parse().unwrap()),
            None,
            Some(DnsTransport::Tcp),
            b"\xab\xcd",
        );

        assert!(receiver.try_recv().is_ok(), "expected an event in channel");
    }

    #[tokio::test]
    async fn test_client_sends_response_to_channel() {
        let (sender, mut receiver) = mpsc::channel(16);
        let client = new_with_sender(sender);

        client.log_response(
            DnstapMessageType::Auth,
            Some("10.0.0.1:53".parse().unwrap()),
            None,
            Some(DnsTransport::Udp),
            (1_000_000, 0),
            b"\x00\x01\x80\x00",
        );

        assert!(receiver.try_recv().is_ok(), "expected an event in channel");
    }

    /// Perform the collector side of the Frame Streams handshake: accept the
    /// client's READY, echo ACCEPT, accept START.
    async fn mock_handshake<S>(
        server: &mut Framed<S, FrameStreamCodec>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ready = server.next().await.unwrap()?;
        match ready {
            FrameStreamItem::Control {
                control_type,
                content_type,
            } => {
                assert_eq!(control_type, CONTROL_READY);
                assert_eq!(
                    content_type.as_deref(),
                    Some(framestream::DNSTAP_CONTENT_TYPE)
                );
            }
            other => panic!("expected READY, got {other:?}"),
        }
        server
            .send(FrameStreamItem::typed_control(CONTROL_ACCEPT))
            .await?;

        let start = server.next().await.unwrap()?;
        match start {
            FrameStreamItem::Control {
                control_type,
                content_type,
            } => {
                assert_eq!(control_type, CONTROL_START);
                assert_eq!(
                    content_type.as_deref(),
                    Some(framestream::DNSTAP_CONTENT_TYPE)
                );
            }
            other => panic!("expected START, got {other:?}"),
        }
        Ok(())
    }

    /// Run `run_stream` over a stream with the default test configuration.
    #[cfg(feature = "metrics")]
    async fn run_test_stream(
        client_side: impl AsyncRead + AsyncWrite + Unpin,
        receiver: &mut mpsc::Receiver<DnstapEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let drop_count = Arc::new(AtomicU64::new(0));
        let enc = EncoderConfig {
            identity: Arc::new(None),
            version: Arc::new(None),
        };
        let budget = ByteBudget::for_buffer(receiver.max_capacity());
        let mut backoff = INITIAL_BACKOFF;
        run_stream(
            client_side,
            receiver,
            &drop_count,
            &budget,
            enc,
            &mut backoff,
            &DnstapMetrics::default(),
        )
        .await
    }

    #[cfg(not(feature = "metrics"))]
    async fn run_test_stream(
        client_side: impl AsyncRead + AsyncWrite + Unpin,
        receiver: &mut mpsc::Receiver<DnstapEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let drop_count = Arc::new(AtomicU64::new(0));
        let enc = EncoderConfig {
            identity: Arc::new(None),
            version: Arc::new(None),
        };
        let budget = ByteBudget::for_buffer(receiver.max_capacity());
        let mut backoff = INITIAL_BACKOFF;
        run_stream(
            client_side,
            receiver,
            &drop_count,
            &budget,
            enc,
            &mut backoff,
        )
        .await
    }
}
