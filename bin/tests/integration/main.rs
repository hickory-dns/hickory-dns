use std::sync::Once;

mod named_https_tests;
mod named_openssl_tests;
mod named_quic_tests;
mod named_rustls_tests;
mod named_test_rsa_dnssec;
mod named_tests;
mod server_harness;

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
