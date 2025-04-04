#[macro_use]
mod authority_battery;
mod config_tests;
mod forwarder;
mod in_memory;
mod named_https_tests;
#[cfg(feature = "metrics")]
mod named_metrics_tests;
mod named_quic_tests;
mod named_rustls_tests;
mod named_test_rsa_dnssec;
mod named_tests;
mod server_harness;
mod sqlite_tests;
mod store_file_tests;
mod store_sqlite_tests;
mod txt_tests;
