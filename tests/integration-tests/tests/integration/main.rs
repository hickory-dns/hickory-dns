use std::sync::Once;

mod catalog_tests;
mod client_future_tests;
mod client_tests;
mod dnssec_client_handle_tests;
mod lookup_tests;
mod name_server_pool_tests;
mod retry_dns_handle_tests;
mod server_future_tests;
mod sqlite_authority_tests;
mod truncation_tests;

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
