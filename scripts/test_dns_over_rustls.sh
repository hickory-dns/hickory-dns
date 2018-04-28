#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

# Build all tests
cargo test --manifest-path resolver/Cargo.toml --features dns-over-rustls
