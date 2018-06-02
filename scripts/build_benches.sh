#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd $trust_dns_dir

# Benchmark tests build only on nightly

cargo bench --no-run
