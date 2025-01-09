# This is based on the dnssec-signzone Dockerfile from
# https://github.com/yevheniya-nosyk/imc2023-ede.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install BIND9 build dependencies and faketime.
RUN apt-get update && apt-get install -y wget xz-utils build-essential libnghttp2-dev libcap-dev libssl-dev perl pkg-config faketime && rm -rf /var/lib/apt/lists/*

# Download source code.
# We use an older version of BIND in order to get a version of dnssec-keygen
# that supports DSA and RSAMD5, and allows selecting how many additional
# iterations to use in NSEC3.
RUN cd /usr/bin && wget https://downloads.isc.org/isc/bind9/9.11.9/bind-9.11.9.tar.gz && tar -xf bind-9.11.9.tar.gz

# Build and install
# Python is disabled because the scripts are not compatible with Python 3.11 and later.
RUN cd /usr/bin/bind-9.11.9 && ./configure --without-python && make && make install

# Create configuration directory and working directory.
RUN mkdir /etc/bind /var/cache/bind

ADD configure_child.sh /
ADD configure_parent.sh /
RUN chmod a+x configure_child.sh configure_parent.sh
