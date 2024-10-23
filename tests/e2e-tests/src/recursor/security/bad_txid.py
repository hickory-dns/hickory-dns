#!/usr/bin/env python3
#
# This server will answer any query with an incorrect transaction ID.
#
from dnslib import DNSRecord, RCODE, RR, QTYPE, A
from dnslib.server import DNSServer

class Resolver(object):
  def resolve(self, request, handler):
    reply = request.reply()
    if reply.header.id == 0:
      reply.header.id = 65535
    else:
      reply.header.id = reply.header.id - 1
    reply.header.rcode = getattr(RCODE,'NOERROR')
    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("192.0.2.1")))
    return reply

if __name__ == "__main__":
  resolver = Resolver()
  server = DNSServer(resolver, address="0.0.0.0", port=53)
  server.start()
