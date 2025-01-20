#!/usr/bin/env python3
#
# This server will not preserve the case of query names in responses.
#
from dnslib import DNSLabel, DNSRecord, RCODE, RR, QTYPE, A
from dnslib.server import BaseResolver, DNSHandler, DNSServer


class Resolver(BaseResolver):
    def resolve(self, request: DNSRecord, _handler: DNSHandler) -> DNSRecord:
        reply = request.reply()
        labels = [bytearray(label) for label in request.q.qname.label]
        for i in range(len(labels)):
            for j in range(len(labels[i])):
                if labels[i][j:j + 1].isalpha():
                    labels[i][j] ^= 0x20  # flip case
        request.q.set_qname(DNSLabel([bytes(label) for label in labels]))
        reply.header.rcode = getattr(RCODE, 'NOERROR')
        if request.q.qtype == QTYPE.A:
            reply.add_answer(
                RR(request.q.qname, QTYPE.A, rdata=A("192.0.2.1")),
            )
        return reply


if __name__ == "__main__":
    resolver = Resolver()
    server = DNSServer(resolver, address="0.0.0.0", port=53)
    server.start()
