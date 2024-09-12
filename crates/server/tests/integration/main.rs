#![recursion_limit = "128"]

use std::sync::Once;

#[macro_use]
mod authority_battery;
mod config_tests;
mod forwarder;
mod in_memory;
mod sqlite_tests;
mod store_file_tests;
mod store_sqlite_tests;
mod timeout_stream_tests;
mod txt_tests;

/// Registers a global default tracing subscriber when called for the first time. This is intended
/// for use in tests.
fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}
