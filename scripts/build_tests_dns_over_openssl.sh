#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo build --tests --manifest-path resolver/Cargo.toml --features dns-over-openssl
cargo build --tests --manifest-path server/Cargo.toml --features dns-over-openssl
cargo build --tests --manifest-path integration-tests/Cargo.toml --features dns-over-openssl
