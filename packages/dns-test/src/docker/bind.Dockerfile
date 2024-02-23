FROM debian:bookworm-slim

# ldns-utils = ldns-{key2ds,keygen,signzone}
# rm = remove default configuration files
RUN apt-get update && \
    apt-get install -y \
        bind9 \
        ldnsutils \
        tshark && \
    rm -f /etc/bind/*
