FROM rust:1-slim-bookworm AS chef
ENV CARGO_INCREMENTAL=0
ENV CARGO_PROFILE_DEV_DEBUG=0
ENV CARGO_PROFILE_DEV_STRIP=true
RUN cargo install cargo-chef --version 0.1.71 --profile dev

# `dns-test` will invoke `docker build` from a temporary directory that contains
# a clone of the hickory repository. `./src` here refers to that clone; not to
# any directory inside the `hickory-dns` repository

FROM chef AS planner
COPY ./src /usr/src/hickory
WORKDIR /usr/src/hickory/conformance
RUN cargo chef prepare

FROM chef AS builder
COPY --from=planner /usr/src/hickory /usr/src/hickory
WORKDIR /usr/src/hickory/conformance
RUN cargo chef cook -p test-server
COPY ./src /usr/src/hickory
RUN cargo build -p test-server

FROM debian:bookworm-slim AS final
RUN apt-get update && \
    apt-get install -y \
    ldnsutils \
    bind9-utils \
    tshark
COPY --from=builder /usr/src/hickory/conformance/target/debug/test-server /usr/bin/test-server
ENV RUST_LOG=debug
