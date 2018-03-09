#!/bin/bash

trust_dns_dir=$(dirname $0)/..

pushd ${trust_dns_dir}
docker run -a STDERR -a STDOUT --rm -v ${PWD}/../:/src rust:latest bash -c "cd src/trust-dns/proto && cargo test --features=mdns $@" | tee target/linux_output.txt
popd
