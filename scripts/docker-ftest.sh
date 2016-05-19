#!/bin/bash

trust_dns_dir=$(dirname $0)/..

docker run -a STDERR -a STDOUT --rm -v ${trust_dns_dir}:/src fnichol/rust:1.8.0 cargo test "$@"
