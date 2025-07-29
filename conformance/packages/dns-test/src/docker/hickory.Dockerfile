FROM rust:1-slim-bookworm AS chef
ENV CARGO_INCREMENTAL=0
ENV CARGO_PROFILE_DEV_DEBUG=0
ENV CARGO_PROFILE_DEV_STRIP=true
RUN cargo install cargo-chef --version 0.1.71 --profile dev
ARG CRYPTO_PROVIDER=aws-lc-rs

# `dns-test` will invoke `docker build` from a temporary directory that contains
# a clone of the hickory repository. `./src` here refers to that clone; not to
# any directory inside the `hickory-dns` repository

FROM chef AS planner
COPY ./src /usr/src/hickory
WORKDIR /usr/src/hickory
RUN cargo chef prepare

FROM chef AS builder
COPY --from=planner /usr/src/hickory/recipe.json /usr/src/hickory/recipe.json
WORKDIR /usr/src/hickory
RUN cargo chef cook -p hickory-dns --bin hickory-dns --features recursor,dnssec-$CRYPTO_PROVIDER && \
    cargo chef cook -p hickory-util --bin dns --features h3-$CRYPTO_PROVIDER,https-$CRYPTO_PROVIDER
COPY ./src /usr/src/hickory
RUN cargo build -p hickory-dns --bin hickory-dns --features recursor,dnssec-$CRYPTO_PROVIDER && \
    cargo build -p hickory-util --bin dns --features h3-$CRYPTO_PROVIDER,https-$CRYPTO_PROVIDER

FROM debian:bookworm-slim AS final
# - ldnsutils is needed for ldns-keygen, ldns-signzone, and ldns-key2dns. These
#   are used to sign zones in name server tests, though the signed zone is later
#   discarded, because Hickory DNS does not yet support serving signed zones.
# - bind9-utils is needed for dnssec-signzone, which is used to sign zones using
#   NSEC3 Opt-Out.
# - tshark is needed for packet captures.
# - openssl is needed to generate a keypair to be used in Hickory DNS's name
#   server configuration.
RUN apt-get update && \
    apt-get install -y \
    ldnsutils \
    bind9-utils \
    tshark \
    openssl

COPY --from=builder /usr/src/hickory/target/debug/hickory-dns /usr/bin/
COPY --from=builder /usr/src/hickory/target/debug/dns /usr/bin/
ENV RUST_LOG=debug
