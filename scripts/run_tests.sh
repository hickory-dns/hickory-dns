#!/bin/bash

# Enumerates all tests and feature variations for each module

# trust-dns-proto
cargo test --manifest-path proto/Cargo.toml
cargo test --manifest-path proto/Cargo.toml --all-features
cargo test --manifest-path proto/Cargo.toml --no-default-features
cargo test --manifest-path proto/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path proto/Cargo.toml --no-default-features --features=dnssec-ring
  
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

# trust-dns-resolver
cargo test --manifest-path resolver/Cargo.toml
cargo test --manifest-path resolver/Cargo.toml --all-features
cargo test --manifest-path resolver/Cargo.toml --no-default-features
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dnssec-ring
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dns-over-native-tls
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dns-over-openssl
cargo test --manifest-path resolver/Cargo.toml --no-default-features --features=dns-over-rustls

# trust-dns-server
cargo test --manifest-path server/Cargo.toml
cargo test --manifest-path server/Cargo.toml --all-features
cargo test --manifest-path server/Cargo.toml --no-default-features
cargo test --manifest-path server/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path server/Cargo.toml --no-default-features --features=dnssec-ring
cargo test --manifest-path server/Cargo.toml --no-default-features --features=dns-over-openssl

# trust-dns-integration-tests
cargo test --manifest-path integration-tests/Cargo.toml
cargo test --manifest-path integration-tests/Cargo.toml --all-features
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features --features=dnssec-ring
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features --features=dns-over-openssl