#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

RSA_2048=rsa_2048.pem
RSA_2048_PUB=rsa_2048_pub.pem

[ -f ${RSA_2048:?} ] || ${OPENSSL:?} genrsa -des3 -out ${RSA_2048:?} 2048
#[ -f ${RSA_2048_PUB:?} ] || ${OPENSSL:?} rsa -in ${RSA_2048:?} -outform PEM -pubout -out ${RSA_2048_PUB:?}