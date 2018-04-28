#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path proto/Cargo.toml --features mdns
cargo test --manifest-path client/Cargo.toml --features mdns
cargo test --manifest-path resolver/Cargo.toml --features mdns
cargo test --manifest-path integration-tests/Cargo.toml --features mdns
