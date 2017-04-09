#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

KEY_FILE=example.key
CSR_FILE=example.csr
CRT_FILE=example.cert
P12_FILE=example.p12

# ec key request
${OPENSSL:?} ecparam -out ${KEY_FILE:?} -name secp256k1 -genkey
${OPENSSL:?} req -new -key ${KEY_FILE:?} -keyform pem -out ${CSR_FILE:?} -subj '/CN=ns.example.com'

# self-signed
${OPENSSL:?} x509 -req -days 365 -in ${CSR_FILE:?} -signkey ${KEY_FILE:?} -out ${CRT_FILE:?}

# pkcs12 chain
${OPENSSL:?} pkcs12 -export -out ${P12_FILE:?} -inkey ${KEY_FILE:?} -in ${CRT_FILE:?} -password pass:mypass
