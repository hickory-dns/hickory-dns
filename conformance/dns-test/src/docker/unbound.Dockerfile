FROM debian:bookworm-slim

# ldns-utils = ldns-{key2ds,keygen,signzone}
# curl, etc. are used to build unbound from source
RUN apt-get update && \
    apt-get install -y \
        ldnsutils \
        bind9-utils \
        nsd \
        tshark \
        curl \
        gcc \
        bison \
        flex \
        libssl-dev \
        libexpat-dev \
        make

ENV UNBOUND_VERSION=1.21.0

RUN curl -L https://github.com/NLnetLabs/unbound/archive/refs/tags/release-$UNBOUND_VERSION.tar.gz | tar xvz -C /tmp/ && \
    cd /tmp/unbound-release-$UNBOUND_VERSION && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-chroot-dir= && \
    make -j$(nproc) && make install && \
    rm -rf /tmp/unbound-release-$UNBOUND_VERSION
RUN useradd --shell /usr/sbin/nologin --system --create-home --home-dir /var/lib/unbound unbound
