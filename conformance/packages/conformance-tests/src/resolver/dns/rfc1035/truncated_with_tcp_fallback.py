#!/usr/bin/env python3
# This server listens on both TCP and UDP ports. It always responds to UDP
# requests with the truncated bit set. The TCP server will allow clients to
# fall back and get a non-truncated response. The record set returned by the
# server changes each time, to allow tests to detect improper caching of
# truncated responses.
from dnslib import DNSLabel, DNSRecord, QTYPE, RCODE, RR, TXT
from dnslib.server import BaseResolver, DNSHandler, DNSServer


class Resolver(BaseResolver):
    def __init__(self, tcp):
        self.tcp = tcp
        self.counter = 0
        self.expected_name = DNSLabel("example.testing.")

    def resolve(self, request: DNSRecord, _handler: DNSHandler) -> DNSRecord:
        reply = request.reply()
        if request.q.qname == self.expected_name:
            reply.header.rcode = RCODE.NOERROR
            if request.q.qtype == QTYPE.TXT:
                counter_text = f"counter={self.counter}".encode("ASCII")
                self.counter += 1
                if self.tcp:
                    rdata = TXT([b"protocol=TCP", counter_text])
                else:
                    reply.header.tc = 1
                    rdata = TXT([b"protocol=UDP", counter_text])
                reply.add_answer(RR(
                    request.q.qname,
                    QTYPE.TXT,
                    ttl=86400,
                    rdata=rdata,
                ))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


if __name__ == "__main__":
    udp_resolver = Resolver(False)
    udp_server = DNSServer(udp_resolver, address="0.0.0.0", port=53)
    udp_server.start_thread()
    tcp_resolver = Resolver(True)
    tcp_server = DNSServer(tcp_resolver, address="0.0.0.0", port=53, tcp=True)
    tcp_server.start()
