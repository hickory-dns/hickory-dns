# !/bin/bash

set -e

OPENSSL=/usr/local/opt/openssl/bin/openssl

trust_dns_dir=$(dirname $0)/..

pushd $trust_dns_dir/tests/test-data

for i in ca.key ca.pem cert-key.pem cert.csr cert.pem cert.p12 ; do
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
O = Trust-DNS
CN = root.example.com

[req_ext]
basicConstraints = CA:TRUE
subjectAltName = @alt_names
 
[alt_names]
DNS.1 = root.example.com
EOF

# CA
echo "----> Generating CA <----"
${OPENSSL:?} genrsa -out ca.key 4096
${OPENSSL:?} req -x509 -new -nodes -key ca.key -days 365 -out ca.pem -verify -config /tmp/ca.conf
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
O = Trust-DNS
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
${OPENSSL:?} genrsa -out cert-key.pem 4096
${OPENSSL:?} req -new -nodes -key cert-key.pem -out cert.csr \
             -verify \
             -config /tmp/cert.conf
${OPENSSL:?} x509 -in ca.pem -inform pem -pubkey -noout > ca.pubkey

echo "----> Signing Cert <----"
${OPENSSL:?} x509 -req -days 365 -in cert.csr -CA ca.pem -CAkey ca.key  -set_serial 0x8771f7bdee982fa6 -out cert.pem -extfile /tmp/cert.conf -extensions req_ext

echo "----> Verifying Cert <----"
${OPENSSL:?} verify -CAfile ca.pem cert.pem

echo "----> Createing PCKS12 <----"
${OPENSSL:?} pkcs12 -export -inkey cert-key.pem -in cert.pem -out cert.p12 -passout pass:mypass -name ns.example.com -chain -CAfile ca.pem


popd