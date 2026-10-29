//! DNSTAP emit-path profiling driver.
//!
//! Reproduces the server's per-request DNSTAP emission pattern (span
//! construction, the query/zone/response events, background sender draining
//! the queue over Frame Streams) against a minimal in-process collector, so
//! profile samples isolate the sender from I/O backpressure. Paced with
//! `yield_now` per request, the producer runs flat out against the sender's
//! bounded channel: the closing payload count reports how much of that burst
//! the sender kept up with.
//!
//! For end-to-end validation against a real collector (vector dnstap source,
//! file sink) point `--socket` at it; the in-process collector, and with it
//! the wait for a completed handshake, is then skipped.
//!
//! Usage:
//!   cargo run --release --example dnstap_profile -p hickory-dnstap -- \
//!     --requests 200000 [--socket /tmp/vector-run/dnstap.sock]
//!
//! The bench collector listens on a Unix domain socket, so this driver is
//! unix-only; on other platforms it prints a note and exits.

fn main() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "the DNSTAP profiling driver needs a Unix domain socket; it only runs on unix platforms"
        );
        std::process::exit(1);
    }

    #[cfg(unix)]
    bench::run();
}

#[cfg(unix)]
mod bench;
