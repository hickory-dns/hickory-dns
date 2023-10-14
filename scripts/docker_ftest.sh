#!/bin/bash

hickory_dns_dir=$(dirname $0)/..

readonly OPTS="--tests --all-features -j 3"
readonly TEST_OPTS="--test-threads=3"

builds=""
builds="${builds} && echo '==> proto' && cd proto && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> resolver' && cd resolver && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> client' && cd client && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> server' && cd server && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> native-tls' && cd native-tls && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> openssl' && cd openssl && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> rustls' && cd rustls && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."
builds="${builds} && echo '==> integration-tests' && cd integration-tests && cargo test ${OPTS} -- ${TEST_OPTS} && cd .."

pushd ${hickory_dns_dir}
docker run \
    --rm \
    -e "RUST_BACKTRACE=full" \
    -e "RUST_LOG=hickory_dns=debug,hickory_proto=debug" \
    -a STDERR -a STDOUT \
    -v ${PWD}/../:/src \
    rust:latest bash \
    -c "cd src/hickory-dns \
        ${builds}
        " | tee target/linux_output.txt
popd
