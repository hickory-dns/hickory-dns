#!/usr/bin/env python3
# This server ignores the first query it receives, and replies to all
# subsequent queries, in order to simulate packet loss.
from dnslib import A, DNSError, DNSLabel, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSHandler, DNSServer


class Resolver(BaseResolver):
    def __init__(self):
        self.first = True
        self.expected_name = DNSLabel("example.testing.")
        self.a = A("192.0.2.1")  # in TEST-NET-1

    def resolve(self, request: DNSRecord, _handler: DNSHandler) -> DNSRecord:
        reply = request.reply()
        if request.q.qname == self.expected_name:
            reply.header.rcode = RCODE.NOERROR
            if request.q.qtype == QTYPE.A:
                if self.first:
                    self.first = False
                    # This will be caught by the try-except block in
                    # DNSHandler.handle(), which results in no response being
                    # sent.
                    raise DNSError("Ignoring first query")
                reply.add_answer(RR(
                    request.q.qname,
                    QTYPE.A,
                    rdata=self.a,
                ))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


if __name__ == "__main__":
    resolver = Resolver()
    server = DNSServer(resolver, address="0.0.0.0", port=53)
    server.start()
