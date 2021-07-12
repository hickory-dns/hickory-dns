FROM rust:1.53-alpine as build-env

COPY . /workspace
WORKDIR /workspace

RUN apk add --no-cache --update musl-dev openssl-dev
# https://users.rust-lang.org/t/sigsegv-with-program-linked-against-openssl-in-an-alpine-container/52172
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

FROM alpine:3.12 as runtime
# https://github.com/mischov/meeseeks/issues/98#issuecomment-636615680
RUN apk add --no-cache --update openssl libgcc
COPY --from=build-env /workspace/target/release/named /usr/bin
# Quickly test the binary is "working" and has no linked libs errors
RUN named --version

ENTRYPOINT [ "named" ]
