FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-dnslib \
        ldnsutils

ENV PYTHONUNBUFFERED=1
