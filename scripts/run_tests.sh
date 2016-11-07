#!/bin/bash -e

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

for i in client server; do
  pushd $i
  cargo build --verbose
  cargo test --verbose
  popd
done
