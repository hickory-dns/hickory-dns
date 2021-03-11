FROM rust:1.50.0-buster as build-env

RUN git clone https://github.com/bluejekyll/trust-dns
WORKDIR /trust-dns
RUN cargo build --release -p trust-dns

FROM gcr.io/distroless/cc-debian10
COPY --from=build-env /trust-dns/target/release/named /

ENTRYPOINT [ "/named" ]
