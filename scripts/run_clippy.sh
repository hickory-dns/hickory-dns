#!/bin/bash

set -e

CARGO=${CARGO:-cargo}

echo "Using cargo: $CARGO"

$CARGO clippy --version || rustup component add clippy

$CARGO clean -p trust-dns-client
$CARGO clean -p trust-dns-proto
$CARGO clean -p trust-dns-server
$CARGO clean -p trust-dns-resolver
$CARGO clean -p trust-dns-rustls
$CARGO clean -p trust-dns-openssl
$CARGO clean -p trust-dns-https
$CARGO clean -p trust-dns-native-tls
$CARGO clean -p trust-dns
$CARGO clean -p trust-dns-compatibility
$CARGO clean -p trust-dns-integration

TARGETS_OPTS="--all --lib --examples --tests --bins"
CLIPPY_OPTS="-D warnings"

for i in crates/* bin tests/compatibility-tests tests/integration-tests ; do
    echo "====> $CARGO clippy --manifest-path ${i}/Cargo.toml ${TARGETS_OPTS:?} -- ${CLIPPY_OPTS:?}"
    $CARGO clippy --manifest-path ${i}/Cargo.toml ${TARGETS_OPTS:?} -- ${CLIPPY_OPTS:?}
    echo "====> $CARGO clippy --manifest-path ${i}/Cargo.toml ${TARGETS_OPTS:?} --all-features -- ${CLIPPY_OPTS:?}"
    $CARGO clippy --manifest-path ${i}/Cargo.toml ${TARGETS_OPTS:?} --all-features -- ${CLIPPY_OPTS:?}
    echo "====> $CARGO clippy --manifest-path ${i}/Cargo.toml ${TARGETS_OPTS:?} --no-default-features -- ${CLIPPY_OPTS:?}"
    $CARGO clippy --manifest-path ${i}/Cargo.toml ${TARGETS_OPTS:?} --no-default-features -- ${CLIPPY_OPTS:?}
done