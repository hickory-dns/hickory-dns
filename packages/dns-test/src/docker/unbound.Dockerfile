FROM debian:bookworm-slim

# dnsutils = dig & delv
# iputils-ping = ping
# ldns-utils = ldns-{key2ds,keygen,signzone}
RUN apt-get update && \
    apt-get install -y \
        dnsutils \
        iputils-ping \
        ldnsutils \
        nsd \
        tshark \
        unbound
