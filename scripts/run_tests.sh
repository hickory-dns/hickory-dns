#!/bin/bash -e

set -x

trust_dns_dir=$(dirname $0)/..
cd $trust_dns_dir

# Enumerates all tests and feature variations for each module

# trust-dns-proto
scripts/run_tests_proto.sh
  
# trust-dns + tls
scripts/run_tests_client.sh

# trust-dns-resolver
scripts/run_tests_resolver.sh

# trust-dns-server
scripts/run_tests_server.sh

# trust-dns-integration-tests
scripts/run_tests_integration_tests.sh