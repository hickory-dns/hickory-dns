FROM rust:1-slim-bookworm

RUN apt-get update && \
    apt-get install -y \
        tshark

COPY ./src /usr/src/hickory
RUN cargo install --path /usr/src/hickory/bin --features recursor --debug
env RUST_LOG=debug
