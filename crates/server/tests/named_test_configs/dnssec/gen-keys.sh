#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

# Install with cargo install kt
KT=kt

RSA_2048=rsa_2048.pem
[ -f ${RSA_2048:?} ] || ${OPENSSL:?} genrsa -des3 -out ${RSA_2048:?} 2048

ECDSA_P256=ecdsa_p256.pem
[ -f ${ECDSA_P256:?} ] || ${OPENSSL:?} ecparam -out ${ECDSA_P256} -name secp256k1 -genkey

ECDSA_P384=ecdsa_p384.pem
[ -f ${ECDSA_P384:?} ] || ${OPENSSL:?} ecparam -out ${ECDSA_P384} -name secp384r1 -genkey

ED25519=ed25519.pk8
[ -f ${ED25519:?} ] || ${KT:?} generate ed25519 --out=${ED25519:?}
