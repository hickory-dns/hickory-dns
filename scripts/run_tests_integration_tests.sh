#!/bin/bash -e

set -x

# Enumerates all tests and feature variations for each module

# trust-dns-integration-tests
cargo test --manifest-path integration-tests/Cargo.toml
cargo test --manifest-path integration-tests/Cargo.toml --all-features
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features --features=dnssec-openssl
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features --features=dnssec-ring
cargo test --manifest-path integration-tests/Cargo.toml --no-default-features --features=dns-over-openssl