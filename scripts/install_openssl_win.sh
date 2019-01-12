#!/bin/bash

# BITS=64
# TARGET=x86_64-pc-windows-msvc
# OPENSSL_VERSION=1_1_0j

# wget -nv "http://slproweb.com/download/Win${BITS}OpenSSL-${OPENSSL_VERSION}.exe"
# ./Win${BITS}OpenSSL-${OPENSSL_VERSION}.exe /SILENT /VERYSILENT /SP- /DIR='C:\\OpenSSL'
# wget -nv "https://curl.haxx.se/ca/cacert.pem" -O 'C:\\OpenSSL\\cacert.pem'

choco install openssl.light