#!/bin/bash

trust_dns_dir=$(dirname $0)/..

openssl req -text -noout -verify -in ${trust_dns_dir}/Kjqmt7v.csr -inform DER -pubkey -out ${trust_dns_dir}crates/proto/src/rr/dnssec/Kjqmt7v.pem
