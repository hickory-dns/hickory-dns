FROM debian:bookworm-slim

# Install PowerDNS Recursor from official repo:
# https://repo.powerdns.com/
RUN apt-get update && \
    apt-get install -y \
        curl \
        gnupg \
        ca-certificates && \
    install -d /etc/apt/keyrings && \
    curl https://repo.powerdns.com/FD380FBB-pub.asc | tee /etc/apt/keyrings/rec-52-pub.asc && \
    echo "deb [signed-by=/etc/apt/keyrings/rec-52-pub.asc] http://repo.powerdns.com/debian bookworm-rec-52 main" > /etc/apt/sources.list.d/pdns.list && \
    echo "Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600" > /etc/apt/preferences.d/rec-52 && \
    apt-get update && \
    apt-get install -y \
        pdns-recursor \
        ldnsutils \
        bind9-utils \
        dnsutils \
        tshark && \
    rm -f /etc/powerdns/recursor.conf && \
    mkdir -p /var/run/pdns-recursor && \
    chown -R pdns:pdns /var/run/pdns-recursor
