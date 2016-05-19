#!/bin/bash -e

trust_dns_dir=$(dirname $0)/..

# reset head
git reset HEAD

# generate the docs
cargo clean
cargo doc --no-deps

git add -f ${trust_dns_dir}/target/doc
git stash

git checkout gh-pages

rm -r ${trust_dns_dir}/target/doc

git stash pop
