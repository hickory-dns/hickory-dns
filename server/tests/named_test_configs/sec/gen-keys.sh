#!/bin/bash

OPENSSL=/usr/local/opt/openssl/bin/openssl

KEY_FILE=example.key
CSR_FILE=example.csr
CRT_FILE=example.cert
P12_FILE=example.p12

# ec key request
echo "====> generating key"
### Apple doesn't allow ECC keys? Ecc will fail native-tls
# ${OPENSSL:?} ecparam -out ${KEY_FILE:?} -name secp256k1 -genkey
### Using RSA for now
${OPENSSL:?} genrsa -out ${KEY_FILE:?} 2048

# echo "====> generating csr"
# ${OPENSSL:?} req -new -key ${KEY_FILE:?} -keyform pem -out ${CSR_FILE:?} \
#                  -subj '/O=TRust-DNS/CN=ns.example.com'

# # self-signed
# echo "====> generating cert"
# ${OPENSSL:?} x509 -req -days 365 -sha256 -in ${CSR_FILE:?} -signkey ${KEY_FILE:?} \
#              -out ${CRT_FILE:?} -outform der \
#              -CA ${CSR_FILE:?} \
#              -trustout \
#              -extfile <(printf "\n[x509v3]\nsubjectAltName=DNS:ns.example.com\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=digitalSignature,keyEncipherment") \
#              -extensions x509v3

## self-signed cert...
echo "====> generating cert"
${OPENSSL:?} req -new -x509 -days 365 -sha256 \
                 -key ${KEY_FILE:?} -keyform pem \
                 -out ${CRT_FILE:?} -outform der \
                 -subj '/O=TRust-DNS/CN=ns.example.com' \
                 -config <(cat /etc/ssl/openssl.cnf <(printf "\n[x509v3]\nsubjectAltName=critical,DNS:ns.example.com\nkeyUsage=critical,digitalSignature,keyAgreement,keyCertSign\nextendedKeyUsage=critical,serverAuth,clientAuth\nbasicConstraints=critical,CA:TRUE,pathlen:0")) \
                 -extensions x509v3 \
                 -reqexts x509v3


${OPENSSL:?} x509 -in ${CRT_FILE:?} -inform der -out ${CRT_FILE:?}.pem

# pkcs12 chain
echo "====> generating p12"
${OPENSSL:?} pkcs12 -export -out ${P12_FILE:?} -inkey ${KEY_FILE:?} -in ${CRT_FILE:?}.pem \
                    -password pass:mypass \
                    -macalg sha256 \
                    -name "ns.example.com" \
                    -info
                
echo "====> verifying certificate"
${OPENSSL:?} verify -CAfile ${CRT_FILE:?}.pem ${CRT_FILE:?}.pem