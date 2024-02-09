FROM rust:1-slim-bookworm

RUN apt-get update && \
    apt-get install -y \
        tshark

RUN cargo install hickory-dns --version 0.24.0 --features recursor --debug
env RUST_LOG=debug
