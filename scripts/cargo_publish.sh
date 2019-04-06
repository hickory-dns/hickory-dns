#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

packages_ordered="proto openssl native-tls rustls https client resolver server"

## dry-run
cargo check

for p in ${packages_ordered:?} ; do
    echo "====> dry-run publish $p"
    cargo publish --verbose --locked --dry-run --manifest-path crates/${p:?}/Cargo.toml
    echo "====> publishing $p"
    cargo publish --verbose --locked --manifest-path crates/${p:?}/Cargo.toml
done

echo "====> dry-run publish util"
cargo publish --verbose --locked --dry-run --manifest-path util/Cargo.toml
echo "====> publishing util"
cargo publish --verbose --locked --manifest-path util/Cargo.toml