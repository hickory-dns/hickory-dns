#!/bin/bash

readonly UBUNTU_VERSION=1ubuntu4

wget https://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-${UBUNTU_VERSION:?}_amd64.deb
wget https://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.0.2g-${UBUNTU_VERSION:?}_amd64.deb

sudo dpkg -i libssl1.0.0_1.0.2g-${UBUNTU_VERSION:?}_amd64.deb
sudo dpkg -i libssl-dev_1.0.2g-${UBUNTU_VERSION:?}_amd64.deb
