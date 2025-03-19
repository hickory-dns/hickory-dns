FROM rust:1-slim-bookworm AS chef
ENV CARGO_INCREMENTAL=0
ENV CARGO_PROFILE_DEV_DEBUG=0
ENV CARGO_PROFILE_DEV_STRIP=true
RUN cargo install cargo-chef --version 0.1.71 --profile dev
ARG DNSSEC_FEATURE=dnssec-ring

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
RUN cargo chef cook -p hickory-dns --bin hickory-dns --features recursor,$DNSSEC_FEATURE && \
    cargo chef cook -p hickory-util --bin dns --features h3-aws-lc-rs,https-aws-lc-rs
COPY ./src /usr/src/hickory
RUN cargo build -p hickory-dns --bin hickory-dns --features recursor,$DNSSEC_FEATURE && \
    cargo build -p hickory-util --bin dns --features h3-aws-lc-rs,https-aws-lc-rs

FROM debian:bookworm-slim AS final
# ldns-utils = ldns-{key2ds,keygen,signzone}
RUN apt-get update && \
    apt-get install -y \
    ldnsutils \
    bind9-utils \
    tshark \
    openssl \
    libssl-dev \
    pkg-config

COPY --from=builder /usr/src/hickory/target/debug/hickory-dns /usr/bin/
COPY --from=builder /usr/src/hickory/target/debug/dns /usr/bin/
ENV RUST_LOG=debug
