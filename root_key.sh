#!/bin/sh

openssl req -text -noout -verify -in Kjqmt7v.csr -inform DER -pubkey -out src/rr/dnssec/Kjqmt7v.pem
