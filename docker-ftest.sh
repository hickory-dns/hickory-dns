#!/bin/sh

docker run -a STDERR -a STDOUT --rm -v ${PWD}:/src fnichol/rust:1.7.0 cargo test "$@"
