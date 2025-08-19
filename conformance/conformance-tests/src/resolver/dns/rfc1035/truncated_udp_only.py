#!/usr/bin/env python3
# This server replies with the truncated bit set over UDP, and changes the
# record set it returns each time. This allows tests to detect improper
# caching of truncated responses.
from dnslib import DNSLabel, DNSRecord, QTYPE, RCODE, RR, TXT
from dnslib.server import BaseResolver, DNSHandler, DNSServer


class Resolver(BaseResolver):
    def __init__(self):
        self.counter = 0
        self.expected_name = DNSLabel("example.testing.")

    def resolve(self, request: DNSRecord, _handler: DNSHandler) -> DNSRecord:
        reply = request.reply()
        if request.q.qname == self.expected_name:
            reply.header.rcode = RCODE.NOERROR
            if request.q.qtype == QTYPE.TXT:
                rdata = TXT(f"counter={self.counter}".encode("ASCII"))
                self.counter += 1
                reply.add_answer(RR(
                    request.q.qname,
                    QTYPE.TXT,
                    ttl=86400,
                    rdata=rdata,
                ))
                reply.header.tc = 1
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


if __name__ == "__main__":
    resolver = Resolver()
    server = DNSServer(resolver, address="0.0.0.0", port=53)
    server.start()
