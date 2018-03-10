#!/bin/bash

trust_dns_dir=$(dirname $0)/..

pushd ${trust_dns_dir}
docker run \
    --rm \
    -e "RUST_BACKTRACE=full" \
    -e "RUST_LOG=trust_dns_proto=debug" \
    -a STDERR -a STDOUT \
    -v ${PWD}/../:/src \
    rust:latest bash \
    -c "cd src/trust-dns && cargo test --features=mdns $@" | tee target/linux_output.txt
popd
