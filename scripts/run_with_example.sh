#!/bin/bash

trust_dns_dir=$(dirname $0)/..
crates_dir=${trust_dns_dir:?}/crates

cargo run -- -d -c ${crates_dir:?}/src/config/test/example.toml -z ${trust_dns_dir}/src/config/test -p 2053
