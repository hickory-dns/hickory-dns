#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

packages_ordered="proto openssl native-tls rustls https client resolver server"

## dry-run
cargo check

for p in ${packages_ordered:?} ; do
    cargo publish --verbose --locked --dry-run --manifest-path ${p:?}/Cargo.toml
    cargo publish --verbose --locked --manifest-path ${p:?}/Cargo.toml     
done
