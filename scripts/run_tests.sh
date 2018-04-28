#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd $trust_dns_dir

# Enumerates all tests and feature variations for each module

scripts/test_all_features.sh
scripts/test_default_features.sh
scripts/test_dns_over_native_tls.sh
scripts/test_dns_over_openssl.sh
scripts/test_dns_over_rustls.sh
scripts/test_dnssec_openssl.sh
scripts/test_dnssec_ring.sh
scripts/test_no_default_features.sh