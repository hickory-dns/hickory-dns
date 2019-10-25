#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path crates/proto/Cargo.toml
cargo test --manifest-path crates/client/Cargo.toml
cargo test --manifest-path util/Cargo.toml
cargo test --manifest-path crates/native-tls/Cargo.toml
cargo test --manifest-path crates/openssl/Cargo.toml
cargo test --manifest-path crates/rustls/Cargo.toml
cargo test --manifest-path crates/https/Cargo.toml
cargo test --manifest-path crates/resolver/Cargo.toml
cargo test --manifest-path crates/server/Cargo.toml
cargo test --manifest-path bin/Cargo.toml
cargo test --manifest-path tests/integration-tests/Cargo.toml

# All examples should go here
cargo run --manifest-path crates/resolver/Cargo.toml --example global_resolver
cargo run --manifest-path crates/resolver/Cargo.toml --example multithreaded_runtime
