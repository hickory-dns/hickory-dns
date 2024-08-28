FROM rust:1-slim-bookworm

# ldns-utils = ldns-{key2ds,keygen,signzone}
RUN apt-get update && \
    apt-get install -y \
        ldnsutils \
        tshark \
        libssl-dev \
        pkg-config

# `dns-test` will invoke `docker build` from a temporary directory that contains
# a clone of the hickory repository. `./src` here refers to that clone; not to
# any directory inside the `hickory-dns` repository
COPY ./src /usr/src/hickory
RUN --mount=type=cache,target=/usr/src/hickory/target cargo build --manifest-path /usr/src/hickory/Cargo.toml -p hickory-dns --features recursor,dnssec-openssl && \
    cp /usr/src/hickory/target/debug/hickory-dns /usr/bin/
ENV RUST_LOG=debug
