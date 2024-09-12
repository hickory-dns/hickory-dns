//! Tests for TCP and UDP stream and client

#![allow(clippy::print_stdout)] // this is a test module

mod tcp;
mod udp;

pub use self::tcp::tcp_client_stream_test;
pub use self::tcp::tcp_stream_test;
pub use self::udp::next_random_socket_test;
pub use self::udp::udp_client_stream_test;
pub use self::udp::udp_stream_test;

/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn subscribe() {
    use std::sync::Once;

    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}
