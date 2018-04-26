#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo build --tests --manifest-path proto/Cargo.toml --all-features  
cargo build --tests --manifest-path client/Cargo.toml --all-features
cargo build --tests --manifest-path native-tls/Cargo.toml --all-features
cargo build --tests --manifest-path openssl/Cargo.toml --all-features
cargo build --tests --manifest-path rustls/Cargo.toml --all-features
cargo build --tests --manifest-path resolver/Cargo.toml --all-features
cargo build --tests --manifest-path server/Cargo.toml --all-features
cargo build --tests --manifest-path integration-tests/Cargo.toml --all-features
