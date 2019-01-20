#!/bin/bash

set -e

cargo clippy --version || rustup component add clippy-preview

cargo clean -p trust-dns
cargo clean -p trust-dns-proto
cargo clean -p trust-dns-server
cargo clean -p trust-dns-resolver
cargo clean -p trust-dns-rustls
cargo clean -p trust-dns-openssl
cargo clean -p trust-dns-https
cargo clean -p trust-dns-native-tls
cargo clean -p trust-dns-compatibility
cargo clean -p trust-dns-integration

TARGETS_OPTS="--all --lib --examples --tests --bins"
CLIPPY_OPTS="-D warnings"

cargo clippy ${TARGETS_OPTS:?} -- ${CLIPPY_OPTS:?}
cargo clippy ${TARGETS_OPTS:?} --all-features -- ${CLIPPY_OPTS:?}
cargo clippy ${TARGETS_OPTS:?} --no-default-features -- ${CLIPPY_OPTS:?}