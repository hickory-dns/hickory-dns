FROM rust:1-slim-bookworm AS bookworm
ENV CARGO_INCREMENTAL=0
ENV CARGO_PROFILE_DEV_DEBUG=0
ENV CARGO_PROFILE_DEV_STRIP=true

# `dns-test` will invoke `docker build` from a temporary directory that contains
# a clone of the hickory repository. `./src` here refers to that clone; not to
# any directory inside the `hickory-dns` repository

FROM bookworm AS builder
COPY ./src /usr/src/hickory
WORKDIR /usr/src/hickory
RUN cd conformance && cargo build -p test-server --release

FROM builder
RUN apt-get update && \
    apt-get install -y \
    ldnsutils \
    bind9-utils \
    tshark
COPY --from=builder /usr/src/hickory/conformance/target/release/test-server /usr/bin/
ENV RUST_LOG=debug
