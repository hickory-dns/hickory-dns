#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path crates/proto/Cargo.toml --features dnssec-ring  
cargo test --manifest-path crates/client/Cargo.toml --features dnssec-ring
cargo test --manifest-path crates/resolver/Cargo.toml --features dnssec-ring
cargo test --manifest-path crates/server/Cargo.toml --features dnssec-ring
cargo test --manifest-path bin/Cargo.toml --features dnssec-ring
cargo test --manifest-path tests/integration-tests/Cargo.toml --features dnssec-ring
