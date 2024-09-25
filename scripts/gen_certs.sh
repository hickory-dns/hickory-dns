#!/bin/bash

set -euxo pipefail

OPENSSL=openssl

hickory_dns_dir=$(dirname $0)/..

pushd $hickory_dns_dir/tests/test-data

for i in ca.key ca.pem cert.key cert.csr cert.pem cert.p12 ; do
    [ -f $i ] && echo "$i exists" && exit 1;
done

echo 

cat <<-EOF > /tmp/ca.conf
[req]
prompt = no
req_extensions = req_ext
distinguished_name = dn

[dn]
C = US
ST = California
L = San Francisco
O = Hickory DNS
CN = root.example.com

[req_ext]
basicConstraints = critical,CA:TRUE
subjectAltName = @alt_names
 
[alt_names]
DNS.1 = root.example.com
EOF

# CA
echo "----> Generating CA <----"
${OPENSSL:?} req -x509 -new -nodes -newkey rsa:4096 -days 365 -keyout ca.key -out ca.pem -config /tmp/ca.conf
${OPENSSL:?} x509 -in ca.pem -out ca.der -outform der  

cat <<-EOF > /tmp/cert.conf
[req]
prompt = no
req_extensions = req_ext
distinguished_name = dn

[dn]

C = US
ST = California
L = San Francisco
O = Hickory DNS
CN = ns.example.com

[req_ext]

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
 
[alt_names]
DNS.1 = ns.example.com
EOF

# Cert
echo "----> Generating CERT  <----"
${OPENSSL:?} req -new -nodes -newkey rsa:4096 -keyout cert.key -out cert.csr \
             -verify \
             -config /tmp/cert.conf

${OPENSSL:?} pkcs8 -in cert.key -inform pem -out cert-key.pk8 -topk8 -nocrypt

${OPENSSL:?} x509 -in ca.pem -inform pem -pubkey -noout > ca.pubkey

echo "----> Signing Cert <----"
${OPENSSL:?} x509 -req -days 365 -in cert.csr -CA ca.pem -CAkey ca.key  -set_serial 0x8771f7bdee982fa6 -out cert.pem -extfile /tmp/cert.conf -extensions req_ext

echo "----> Verifying Cert <----"
${OPENSSL:?} verify -CAfile ca.pem cert.pem

echo "----> Creating PKCS12 <----"
${OPENSSL:?} pkcs12 -export -inkey cert.key -in cert.pem -out cert.p12 -passout pass:mypass -name ns.example.com -chain -CAfile ca.pem


popd
