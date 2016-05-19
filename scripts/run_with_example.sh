#!/bin/bash

trust_dns_dir=$(dirname $0)/..

cargo run -- -d -c ${trust_dns_dir}/src/config/test/example.toml -z ${trust_dns_dir}/src/config/test -p 2053
