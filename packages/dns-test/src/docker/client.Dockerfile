FROM debian:bookworm-slim

# dnsutils = dig & delv
# iputils-ping = ping
RUN apt-get update && \
    apt-get install -y \
        dnsutils \
        iputils-ping
