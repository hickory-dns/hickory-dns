#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path proto/Cargo.toml --features dnssec-ring  
cargo test --manifest-path client/Cargo.toml --features dnssec-ring
cargo test --manifest-path resolver/Cargo.toml --features dnssec-ring
cargo test --manifest-path server/Cargo.toml --features dnssec-ring
cargo test --manifest-path integration-tests/Cargo.toml --features dnssec-ring
