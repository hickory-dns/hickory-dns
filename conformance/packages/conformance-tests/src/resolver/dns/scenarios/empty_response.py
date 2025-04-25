#!/usr/bin/env python3
# This server sends empty responses, not even including an SOA record.
from dnslib import DNSRecord
from dnslib.server import BaseResolver, DNSHandler, DNSServer


class Resolver(BaseResolver):
    def resolve(self, request: DNSRecord, _handler: DNSHandler) -> DNSRecord:
        return request.reply()


if __name__ == "__main__":
    resolver = Resolver()
    server = DNSServer(resolver, address="0.0.0.0", port=53)
    server.start()
