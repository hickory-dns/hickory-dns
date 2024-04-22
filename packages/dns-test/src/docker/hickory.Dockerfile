FROM rust:1-slim-bookworm

RUN apt-get update && \
    apt-get install -y \
        tshark

# `dns-test` will invoke `docker build` from a temporary directory that contains
# a clone of the hickory repository. `./src` here refers to that clone; not to
# any directory inside the `dns-test` repository
COPY ./src /usr/src/hickory
RUN cargo install --path /usr/src/hickory/bin --features recursor --debug && \
    mkdir /etc/hickory
env RUST_LOG=debug
