#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path proto/Cargo.toml
cargo test --manifest-path client/Cargo.toml
cargo test --manifest-path util/Cargo.toml
cargo test --manifest-path native-tls/Cargo.toml
cargo test --manifest-path openssl/Cargo.toml
cargo test --manifest-path rustls/Cargo.toml
cargo test --manifest-path https/Cargo.toml
cargo test --manifest-path resolver/Cargo.toml
cargo test --manifest-path server/Cargo.toml
cargo test --manifest-path integration-tests/Cargo.toml

# All examples should go here
cargo run --manifest-path resolver/Cargo.toml --example global_resolver
cargo run --manifest-path resolver/Cargo.toml --example multithreaded_runtime
