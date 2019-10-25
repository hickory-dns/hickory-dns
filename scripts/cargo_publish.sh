#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

packages_ordered="crates/proto crates/openssl crates/native-tls crates/rustls crates/https crates/client crates/resolver crates/server bin util"

## dry-run
cargo check

for p in ${packages_ordered:?} ; do
    cargo update -p trust-dns-proto
    cargo update -p trust-dns-client
    cargo update -p trust-dns-resolver
    cargo update -p trust-dns-server
    echo "====> dry-run publish $p"
    cargo publish --verbose --locked --dry-run --manifest-path ${p:?}/Cargo.toml
    echo "====> publishing $p"
    cargo publish --verbose --locked --manifest-path ${p:?}/Cargo.toml
done
