#!/bin/bash -e

set -x

# Enumerates all tests and feature variations for each module

# trust-dns-server
cargo test --manifest-path server/Cargo.toml
cargo test --manifest-path server/Cargo.toml --all-features
cargo test --manifest-path server/Cargo.toml --no-default-features
cargo test --manifest-path server/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path server/Cargo.toml --no-default-features --features=dnssec-ring
cargo test --manifest-path server/Cargo.toml --no-default-features --features=dns-over-openssl
