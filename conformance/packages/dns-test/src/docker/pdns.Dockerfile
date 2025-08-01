FROM debian:bookworm-slim

# Install PowerDNS Recursor and Authoritative Server from official repo:
# https://repo.powerdns.com/
RUN apt-get update && \
    apt-get install -y \
        curl \
        gnupg \
        ca-certificates && \
    install -d /etc/apt/keyrings && \
    curl https://repo.powerdns.com/FD380FBB-pub.asc | tee /etc/apt/keyrings/FD380FBB-pub.asc && \
    echo "deb [signed-by=/etc/apt/keyrings/FD380FBB-pub.asc] http://repo.powerdns.com/debian bookworm-rec-52 main" > /etc/apt/sources.list.d/pdns-rec.list && \
    echo "deb [signed-by=/etc/apt/keyrings/FD380FBB-pub.asc] http://repo.powerdns.com/debian bookworm-auth-49 main" > /etc/apt/sources.list.d/pdns-auth.list && \
    echo "Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600" > /etc/apt/preferences.d/pdns && \
    apt-get update && \
    apt-get install -y \
        pdns-recursor \
        pdns-server \
        ldnsutils \
        bind9-utils \
        dnsutils \
        tshark && \
    rm -f /etc/powerdns/recursor.conf && \
    rm -f /etc/powerdns/pdns.conf && \
    mkdir -p /var/run/pdns-recursor && \
    mkdir -p /var/run/pdns && \
    chown -R pdns:pdns /var/run/pdns-recursor && \
    chown -R pdns:pdns /var/run/pdns && \
    pdnsutil create-bind-db /var/run/pdns/dnssec.db && \
    chown pdns:pdns /var/run/pdns/dnssec.db
