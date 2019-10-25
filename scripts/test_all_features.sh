#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path crates/proto/Cargo.toml --all-features  
cargo test --manifest-path crates/client/Cargo.toml --all-features
cargo test --manifest-path util/Cargo.toml --all-features
cargo test --manifest-path crates/native-tls/Cargo.toml --all-features
cargo test --manifest-path crates/openssl/Cargo.toml --all-features
cargo test --manifest-path crates/rustls/Cargo.toml --all-features
cargo test --manifest-path crates/https/Cargo.toml --all-features
cargo test --manifest-path crates/resolver/Cargo.toml --all-features
cargo test --manifest-path crates/server/Cargo.toml --all-features
cargo test --manifest-path bin/Cargo.toml --all-features
cargo test --manifest-path tests/integration-tests/Cargo.toml --all-features
