echo on

REM This script is designed to work with AppVeyor
REM Each test suite should be enabled with one of the environment
REM variables

set RUST_BACKTRACE=full

if [%DEFAULT_SUITE%] EQU [1] (
    cargo test --manifest-path proto\Cargo.toml
    cargo test --manifest-path client\Cargo.toml
    cargo test --manifest-path resolver\Cargo.toml
    cargo test --manifest-path server\Cargo.toml
    cargo test --manifest-path integration-tests\Cargo.toml
    cargo run --manifest-path resolver\Cargo.toml --example global_resolver
    cargo run --manifest-path resolver\Cargo.toml --example multithreaded_runtime
)

if [%ALL_FEATURES_SUITE%] EQU [1] (
    cargo test --manifest-path proto\Cargo.toml --all-features
    cargo test --manifest-path client\Cargo.toml --all-features
    cargo test --manifest-path resolver\Cargo.toml --all-features
    cargo test --manifest-path server\Cargo.toml --all-features
    cargo test --manifest-path integration-tests\Cargo.toml --all-features
)

if [%NO_DEFAULT_FEATURES_SUITE%] EQU [1] (
    cargo test --manifest-path proto\Cargo.toml --no-default-features
    cargo test --manifest-path client\Cargo.toml --no-default-features
    cargo test --manifest-path resolver\Cargo.toml --no-default-features
    cargo test --manifest-path server\Cargo.toml --no-default-features
    cargo test --manifest-path integration-tests\Cargo.toml --no-default-features
)

if [%DNSSEC_OPENSSL_SUITE%] EQU [1] (
    cargo test --manifest-path proto\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path client\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path resolver\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path server\Cargo.toml --no-default-features --features=dnssec-openssl
    cargo test --manifest-path integration-tests\Cargo.toml --no-default-features --features=dnssec-openssl
)

if [%DNSSEC_RING_SUITE%] EQU [1] (
    cargo test --manifest-path proto\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path client\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path resolver\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path server\Cargo.toml --no-default-features --features=dnssec-ring
    cargo test --manifest-path integration-tests\Cargo.toml --no-default-features --features=dnssec-ring
)

if [%DNS_OVER_TLS_SUITE%] EQU [1] (
    cargo test --manifest-path native-tls\Cargo.toml
    cargo test --manifest-path openssl\Cargo.toml
    cargo test --manifest-path rustls\Cargo.toml
    cargo test --manifest-path https\Cargo.toml
    cargo test --manifest-path resolver\Cargo.toml --features=dns-over-native-tls
    cargo test --manifest-path resolver\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path server\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path integration-tests\Cargo.toml --features=dns-over-openssl
    cargo test --manifest-path resolver\Cargo.toml --features=dns-over-rustls
)

if %ERRORLEVEL% NEQ 0 (
  echo Tests failed
  exit 1
)