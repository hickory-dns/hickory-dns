#!/bin/bash -e

set -x

# Enumerates all tests and feature variations for each module

# trust-dns-resolver
cargo test --manifest-path resolver/Cargo.toml
cargo test --manifest-path resolver/Cargo.toml --all-features
cargo test --manifest-path resolver/Cargo.toml --no-default-features
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dnssec-ring
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dns-over-native-tls
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dns-over-openssl
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dns-over-rustls
