#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path crates/proto/Cargo.toml --no-default-features --features tokio-compat
cargo test --manifest-path crates/client/Cargo.toml --no-default-features
cargo test --manifest-path util/Cargo.toml --no-default-features
cargo test --manifest-path crates/native-tls/Cargo.toml --no-default-features
cargo test --manifest-path crates/openssl/Cargo.toml --no-default-features
cargo test --manifest-path crates/rustls/Cargo.toml --no-default-features
cargo test --manifest-path crates/https/Cargo.toml --no-default-features
cargo test --manifest-path crates/resolver/Cargo.toml --no-default-features --features tokio
cargo test --manifest-path crates/server/Cargo.toml --no-default-features
cargo test --manifest-path bin/Cargo.toml --no-default-features
cargo test --manifest-path tests/integration-tests/Cargo.toml --no-default-features
