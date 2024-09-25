#!/bin/bash

set e
set x

OPENSSL=${OPENSSL:-openssl}

KEY_FILE=example.key
CSR_FILE=example.csr
CRT_FILE=example.cert
P12_FILE=example.p12

# ec key request
echo "====> generating key"
### Apple doesn't allow ECC keys? Ecc will fail native-tls
# ${OPENSSL:?} ecparam -out ${KEY_FILE:?}.pem -outform pem -name secp256k1 -genkey
### Using RSA for now
${OPENSSL:?} genrsa -out ${KEY_FILE:?}.pem 2048

${OPENSSL:?} pkey -in ${KEY_FILE:?}.pem -inform pem -out ${KEY_FILE:?} -outform der

## self-signed cert...
echo "====> generating cert"
${OPENSSL:?} req -new -x509 -days 365 -sha256 \
                 -key ${KEY_FILE:?} -keyform der \
                 -out ${CRT_FILE:?} -outform der \
                 -subj '/O=Hickory DNS/CN=ns.example.com' \
                 -config <(cat /etc/ssl/openssl.cnf <(printf "\n[x509v3]\nsubjectAltName=critical,DNS:ns.example.com\nkeyUsage=critical,digitalSignature,keyAgreement,keyCertSign\nextendedKeyUsage=critical,serverAuth,clientAuth\nbasicConstraints=critical,pathlen:0")) \
                 -extensions x509v3 \
                 -reqexts x509v3


${OPENSSL:?} x509 -in ${CRT_FILE:?} -inform der -out ${CRT_FILE:?}.pem

# pkcs12 chain
echo "====> generating p12"
${OPENSSL:?} pkcs12 -export -out ${P12_FILE:?} -inkey ${KEY_FILE:?}.pem -in ${CRT_FILE:?}.pem \
                    -password pass:mypass \
                    -macalg sha256 \
                    -name "ns.example.com" \
                    -info
                
echo "====> verifying certificate"
${OPENSSL:?} verify -CAfile ${CRT_FILE:?}.pem ${CRT_FILE:?}.pem
