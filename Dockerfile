FROM rust:1.50.0-buster as build-env

RUN git clone https://github.com/bluejekyll/trust-dns
RUN apt-get update
RUN apt-get install -y musl-tools openssl libssl-dev
WORKDIR /trust-dns
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release -p trust-dns --target=x86_64-unknown-linux-musl

FROM gcr.io/distroless/cc
COPY --from=build-env /trust-dns/target/x86_64-unknown-linux-musl/release/named /

ENTRYPOINT [ "/named" ]
