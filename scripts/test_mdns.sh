#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path crates/proto/Cargo.toml --features mdns
cargo test --manifest-path crates/client/Cargo.toml --features mdns
cargo test --manifest-path crates/resolver/Cargo.toml --features mdns
cargo test --manifest-path tests/integration-tests/Cargo.toml --features mdns
