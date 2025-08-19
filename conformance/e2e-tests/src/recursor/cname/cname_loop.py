#!/usr/bin/env python3
#
from dnslib import DNSRecord, RCODE, RR, QTYPE, NS
from dnslib.server import DNSServer

class Resolver(object):
  def resolve(self, request, handler):
    qname = request.get_q().get_qname()
    tokens = str(qname).split("-")
    round = int(tokens[1]) + 1 if len(tokens) == 3 else 0

    reply = request.reply()
    reply.header.rcode = getattr(RCODE,'NOERROR')

    # Stop before we hit the recursion depth limit
    if round > 9:
      reply.add_answer(*RR.fromZone(f"{qname} IN A 127.0.0.1"))
    else:
      for i in range(40):
        host = f"c-{round}-{i}.testing."
        reply.add_answer(*RR.fromZone(f"{qname} IN CNAME {host}"))
    reply.auth = []
    return reply

if __name__ == "__main__":
  resolver = Resolver()
  server = DNSServer(resolver, address="0.0.0.0", port=53)
  server.start()
