#!/bin/bash

wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-1ubuntu4.10_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.0.2g-1ubuntu4.10_amd64.deb

sudo dpkg -i libssl1.0.0_1.0.2g-1ubuntu4.10_amd64.deb
sudo dpkg -i libssl-dev_1.0.2g-1ubuntu4.10_amd64.deb
