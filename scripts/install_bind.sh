#!/bin/sh

set -e

## This must run after OpenSSL installation

echo "----> downloading bind"
wget https://downloads.isc.org/isc/bind9/9.11.7/bind-9.11.7.tar.gz
tar -xzf bind-9.11.7.tar.gz

echo "----> compiling bind"
cd bind-9.11.7
./configure
make

## export TDNS_BIND_PATH=bin/named/named
