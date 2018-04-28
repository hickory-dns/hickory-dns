#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path proto/Cargo.toml --no-default-features
cargo test --manifest-path client/Cargo.toml --no-default-features
cargo test --manifest-path util/Cargo.toml --no-default-features
cargo test --manifest-path native-tls/Cargo.toml --no-default-features
cargo test --manifest-path openssl/Cargo.toml --no-default-features
cargo test --manifest-path rustls/Cargo.toml --no-default-features
cargo test --manifest-path resolver/Cargo.toml --no-default-features
cargo test --manifest-path server/Cargo.toml --no-default-features
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features
