echo on

REM This script is designed to work with AppVeyor
REM Each test suite should be enabled with one of the environment
REM variables

set RUST_BACKTRACE=full

if [%DEFAULT_SUITE%] EQU [1] (
    cargo test --manifest-path crates\proto\Cargo.toml
    cargo test --manifest-path crates\client\Cargo.toml
    cargo test --manifest-path crates\resolver\Cargo.toml
    cargo test --manifest-path crates\server\Cargo.toml
    cargo test --manifest-path tests\integration-tests\Cargo.toml
    cargo run --manifest-path crates\resolver\Cargo.toml --example global_resolver
    cargo run --manifest-path bin\Cargo.toml --example global_resolver
    cargo run --manifest-path crates\resolver\Cargo.toml --example multithreaded_runtime
)

if [%ALL_FEATURES_SUITE%] EQU [1] (
    cargo test --manifest-path crates\proto\Cargo.toml --all-features
    cargo test --manifest-path crates\client\Cargo.toml --all-features
    cargo test --manifest-path crates\resolver\Cargo.toml --all-features
    cargo test --manifest-path crates\server\Cargo.toml --all-features
    cargo test --manifest-path bin\Cargo.toml --all-features
    cargo test --manifest-path tests\integration-tests\Cargo.toml --all-features
)

if [%NO_DEFAULT_FEATURES_SUITE%] EQU [1] (
    cargo test --manifest-path crates\proto\Cargo.toml --no-default-features --features tokio-compat
    cargo test --manifest-path crates\client\Cargo.toml --no-default-features
    cargo test --manifest-path crates\resolver\Cargo.toml --no-default-features --features tokio
    cargo test --manifest-path crates\server\Cargo.toml --no-default-features
    cargo test --manifest-path bin\Cargo.toml --no-default-features
    cargo test --manifest-path tests\integration-tests\Cargo.toml --no-default-features
)

if [%DNSSEC_OPENSSL_SUITE%] EQU [1] (
    cargo test --manifest-path crates\proto\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path crates\client\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path crates\resolver\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path crates\server\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path bin\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path tests\integration-tests\Cargo.toml --no-default-features --features=dnssec-openssl
)

if [%DNSSEC_RING_SUITE%] EQU [1] (
    cargo test --manifest-path crates\proto\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path crates\client\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path crates\resolver\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path crates\server\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path bin\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path tests\integration-tests\Cargo.toml --no-default-features --features=dnssec-ring
)

if [%DNS_OVER_TLS_SUITE%] EQU [1] (
    cargo test --manifest-path crates\native-tls\Cargo.toml
    cargo test --manifest-path crates\openssl\Cargo.toml
    cargo test --manifest-path crates\rustls\Cargo.toml
    cargo test --manifest-path crates\https\Cargo.toml
    cargo test --manifest-path crates\resolver\Cargo.toml --features=dns-over-native-tls
    cargo test --manifest-path crates\resolver\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path crates\server\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path bin\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path tests\integration-tests\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path crates\resolver\Cargo.toml --features=dns-over-rustls
)

if %ERRORLEVEL% NEQ 0 (
  echo Tests failed
  exit 1
)
