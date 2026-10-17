//! The profiling driver body, unix-only; usage docs live in `main.rs`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use hickory_dnstap::{DnstapConfig, DnstapEndpoint, DnstapLayer};
use test_support::framestream;
use tokio::net::UnixListener;
use tracing_subscriber::layer::SubscriberExt;

const TARGET: &str = "hickory_server::dnstap";

/// Payload frames counted by the collector; every request emits one query
/// and one response frame, so the expected count is twice the number of
/// requests. A short count means the sender's channel overflowed.
static PAYLOADS: AtomicU64 = AtomicU64::new(0);

/// Set once the collector has read the client's START frame.
static CONNECTED: AtomicBool = AtomicBool::new(false);

const QUERY_WIRE: &[u8] = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00";
const RESPONSE_WIRE: &[u8] = b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x09\x92\x00\x04\xc0\x21\x93\x96\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00";

fn requests() -> usize {
    arg_value("--requests")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000)
}

/// Any `--socket` other than the bench collector points at a real one.
fn socket_path() -> PathBuf {
    arg_value("--socket")
        .map(PathBuf::from)
        .unwrap_or_else(bench_socket)
}

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    args.find(|a| a == name)?;
    args.next()
}

fn bench_socket() -> PathBuf {
    PathBuf::from("/tmp/hickory-dnstap-bench.sock")
}

/// Bind the bench socket before the client starts.
///
/// A listener that appears after the client's first connect attempt costs a
/// failed connection plus the reconnect backoff, during which the producer
/// can already exhaust its whole workload into the channel.
fn bench_listener() -> UnixListener {
    let path = bench_socket();
    let _ = std::fs::remove_file(&path);
    UnixListener::bind(&path).expect("bind bench socket")
}

/// Minimal Frame Streams collector: answers READY with an ACCEPT carrying the
/// DNSTAP content type, reads START, then discards every payload byte. No
/// decoding or sink work, so the profile is the sender's alone.
async fn run_collector(listener: UnixListener) {
    PAYLOADS.store(0, Ordering::Relaxed);
    CONNECTED.store(false, Ordering::Relaxed);
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            framestream::handshake(&mut stream).await;
            CONNECTED.store(true, Ordering::Relaxed);
            framestream::collect(&mut stream, |_payload| {
                PAYLOADS.fetch_add(1, Ordering::Relaxed);
            })
            .await;
        });
    }
}

/// Wait for the in-process collector to see START.
///
/// Without this the producer can emit its entire workload while the sender is
/// still establishing the connection, which leaves a full channel behind and
/// reads as a stalled drain rather than a lost race.
async fn wait_for_connected() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !CONNECTED.load(Ordering::Relaxed) {
        if tokio::time::Instant::now() > deadline {
            eprintln!("warning: no collector handshake after 5s, starting anyway");
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::main(flavor = "multi_thread")]
pub(crate) async fn run() {
    let count = requests();
    let bench = socket_path() == bench_socket();

    // Bind before the client starts, then hand the sender a live listener.
    let _collector = bench.then(|| tokio::spawn(run_collector(bench_listener())));

    let (layer, connection) = DnstapLayer::new(config());
    // The binary uses a global subscriber; a thread-local default dies at the
    // first await point of a multi-thread runtime.
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
        .expect("set global tracing subscriber");
    connection.start();

    if bench {
        wait_for_connected().await;
    }

    let src_octets = Ipv4Addr::new(192, 0, 2, 7).octets();
    let server_octets = Ipv4Addr::new(192, 0, 2, 53).octets();
    for _ in 0..count {
        let span = tracing::span!(
            target: TARGET,
            tracing::Level::TRACE,
            "dns.request",
            src_addr_bytes = &src_octets[..],
            src_port = 40043u64,
            protocol = %"udp",
            server_addr_bytes = &server_octets[..],
            server_port = 53u64,
            class = %"client",
        );

        {
            let _guard = span.enter();
            tracing::event!(target: TARGET, tracing::Level::TRACE, kind = "query", message_bytes = QUERY_WIRE);
            tracing::event!(target: TARGET, tracing::Level::TRACE, kind = "zone", query_zone = &b"\x07example\x03com\x00"[..]);
            tracing::event!(target: TARGET, tracing::Level::TRACE, kind = "response", message_bytes = RESPONSE_WIRE);
        }
        tokio::task::yield_now().await;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    eprintln!(
        "PAYLOADS collected: {}/{}",
        PAYLOADS.load(Ordering::Relaxed),
        count * 2
    );
}

fn config() -> DnstapConfig {
    DnstapConfig {
        endpoint: DnstapEndpoint::Unix(socket_path()),
        buffer_size: 4096,
        log_auth_query: true,
        log_auth_response: true,
        log_client_query: true,
        log_client_response: true,
        ..DnstapConfig::default()
    }
}
