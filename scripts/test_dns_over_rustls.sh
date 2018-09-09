#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path resolver/Cargo.toml --features dns-over-rustls,dns-over-https-rustls
cargo test --manifest-path server/Cargo.toml --features dns-over-https-rustls,dns-over-rustls
cargo test --manifest-path integration-tests/Cargo.toml --features dns-over-https-rustls
