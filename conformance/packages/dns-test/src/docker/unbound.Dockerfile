FROM debian:bookworm-slim

# ldns-utils = ldns-{key2ds,keygen,signzone}
RUN apt-get update && \
    apt-get install -y \
        ldnsutils \
        nsd \
        tshark \
        unbound
