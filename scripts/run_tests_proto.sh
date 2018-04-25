#!/bin/bash -e

set -x

# Enumerates all tests and feature variations for each module

# trust-dns-proto
cargo test --manifest-path proto/Cargo.toml
cargo test --manifest-path proto/Cargo.toml --all-features
cargo test --manifest-path proto/Cargo.toml --no-default-features
cargo test --manifest-path proto/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path proto/Cargo.toml --no-default-features --features=dnssec-ring
