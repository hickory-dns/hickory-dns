#!/bin/bash -e

set -x

# Enumerates all tests and feature variations for each module
  
# trust-dns
cargo test --manifest-path client/Cargo.toml
cargo test --manifest-path client/Cargo.toml --all-features
cargo test --manifest-path client/Cargo.toml --no-default-features
cargo test --manifest-path client/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path client/Cargo.toml --no-default-features --features=dnssec-ring

# trust-dns-*tls
cargo test --manifest-path native-tls/Cargo.toml
cargo test --manifest-path openssl/Cargo.toml
cargo test --manifest-path rustls/Cargo.toml
