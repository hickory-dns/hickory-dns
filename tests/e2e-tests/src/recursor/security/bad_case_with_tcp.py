#!/usr/bin/env python3
#
# This server will not preserve the case of query names in responses.
#
from dnslib import DNSLabel, DNSRecord, RCODE, RR, QTYPE, A
from dnslib.server import BaseResolver, DNSHandler, DNSServer


class Resolver(BaseResolver):
    def __init__(self, tcp):
        self.tcp = tcp

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
            rdata = A("192.0.2.2") if self.tcp else A("192.0.2.1")
            reply.add_answer(
                RR(request.q.qname, QTYPE.A, rdata=rdata),
            )
        return reply


if __name__ == "__main__":
    udp_resolver = Resolver(False)
    udp_server = DNSServer(udp_resolver, address="0.0.0.0", port=53)
    udp_server.start_thread()
    tcp_resolver = Resolver(True)
    tcp_server = DNSServer(tcp_resolver, address="0.0.0.0", port=53, tcp=True)
    tcp_server.start()
