#!/bin/bash

trust_dns_dir=$(dirname $0)/..

pushd ${trust_dns_dir}
docker run -a STDERR -a STDOUT --rm -v ${PWD}/../:/src bfry/rust:stable bash -c "cd trust-dns && scripts/run_tests.sh $@" | tee target/linux_output.txt

popd
