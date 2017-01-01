#!/bin/bash -e

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

for i in client server; do
  pushd $i
  echo "$0: updating cargo on $i"
  cargo update
  popd
done

for i in client server; do
  pushd $i
  echo "$0: building cargo on $i"
  cargo build
  popd
done

for i in client server; do
  pushd $i
  echo "$0: testing cargo on $i"
  cargo test
  popd
done

for i in client server; do
  pushd $i
  echo "$0: publishing cargo on $i"
  cargo publish
  popd
done
