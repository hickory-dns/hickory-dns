#!/bin/sh

## This must run after OpenSSL installation

echo "----> downloading bind"
wget -O bind-9.11.0-P1.tar.gz https://www.isc.org/downloads/file/bind-9-11-0-p1/
tar -xzf bind-9.11.0-P1.tar.gz

echo "----> compiling bind"
cd bind-9-11-0-p1
.configure
make

## export TDNS_BIND_PATH=bin/named/named